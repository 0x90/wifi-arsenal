/*
 *  Wireless Network Monitor
 *
 *  Copyright 2011 David Garcia Villalba, Daniel López Rovira, Marc Portoles Comeras and Albert Cabellos Aparicio
 *
 *  This file is part of wmon.
 *
 *  wmon is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  wmon is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with wmon.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "CaptureStorage.h"
#include "NetStructures.h"
#include "NetID.h"
#include "GUIEventDispatcher.h"
#include "UpdateChannelEvent.h"
#include <cstring>
#include <ctime>
#include <libtrace.h>
#include <string.h>

CaptureStorage::CaptureStorage() {
    channel = 0;
    runAnalyzer = false;
    startAnalyzer();
}

CaptureStorage::~CaptureStorage() {
    stopAnalyzer();
}

void CaptureStorage::setChannel(unsigned short channel) {
    this->channel = channel;
}

void CaptureStorage::addCapture(const unsigned char *packet, unsigned int len, long int sec, long int usec) {
    unsigned short channel = this->channel;
    
    // Calculating pointers to headers
    ieee80211_radiotap_header* taph = (ieee80211_radiotap_header*) packet;
    ieee80211_mac_header *mach = (ieee80211_mac_header*) (packet + taph->it_len);
    ieee80211_management_frame *beacons = (ieee80211_management_frame*) (packet + taph->it_len + sizeof(ieee80211_mac_header));
    tag_param* param = (tag_param*) (packet + taph->it_len + sizeof(ieee80211_mac_header) + sizeof(ieee80211_management_frame));
    len -= taph->it_len + sizeof(ieee80211_mac_header) + sizeof(ieee80211_management_frame);
    
    // Obtain info from Tagged Parameters
    bool wep = beacons->info.fields.privacy, wpa = false, wpa2 = false;
    char ssid[33]; ssid[0] = '\0';
    while (len > 4) { // Temporal fix for Atheros with CRC
        switch (param->element_id) {
            case 0: // SSID
                ssid[param->length] = '\0';
                memcpy(ssid, &((ssid_t*) param)->ssid, param->length);
                break;
            case 3: // Channel
                // Only save the current channel captures
                if (channel != (unsigned short) ((ds_t*) param)->channel) return;
                break;
            case 48: // RSN
                wpa2 = true;
                break;
            case 221: // Vendor Specific
                static unsigned char WPATAG[4] = {0x00, 0x50, 0xf2, 0x01}; // MICROSOFTOUI[3] = {0x00, 0x50, 0xf2};
                wpa = wpa or memcmp(((vendorspecific_t*) param)->data, WPATAG, 4) == 0;
                break;
        }
        
        /*
         * Note: The following if condition is added based on a particular use case 
         * The problem should be debugged better but in certain locations some packets are 
         * handled as beacons but they do not follow the standard structure
         * This problem should be debugged better.
         */
        unsigned int tagLength = param->length + sizeof(tag_param);
        if (tagLength <= len) { // protect against malformed/unexpected beacon parameters
            len -= tagLength;
            param = (tag_param*) (((char *) param) + tagLength);
        }
        else { //skip analysis of this type of beacons when detected
            len = 0;
        }
    }
    
    NetID net(mach->bssid, ssid);           // Generating the NetID struct with {BSSID, SSID}
    BeaconInfo bi;                          // Structure with relevant beacon info
    bi.timestamp = beacons->timestamp;
    bi.interval = beacons->interval*1024;
    bi.sec = sec;
    bi.usec = usec;
    
    //trace_get_wireless_rate(taph, TRACE_TYPE_80211_RADIO, &bi.rate);
    bi.hasRSSI = trace_get_wireless_signal_strength_dbm(taph, TRACE_TYPE_80211_RADIO, &bi.rssi) != 0;
    
    bool newNetwork = nets.count(net) == 0;
    
    NetInfo* neti = &nets[net]; // Obtain the NetInfo struct pointer of the network NetID. If its a new network the map creates a new entry.
    
    neti->addBeaconInfo(bi);
    
    if (neti->getInterval() != bi.interval) neti->setInterval(bi.interval); // Updates dynamic information: Beacon interval
    
    if (newNetwork or neti->getChannel() != channel) {
        if (not newNetwork) netsByChannel[neti->getChannel()].remove(net); // neti->getChannel() != channel
        netsByChannel[channel].push_back(net);
        neti->setChannel(channel);   
    }

    neti->setWEP(wep);
    neti->setWPA(wpa);
    neti->setWPA2(wpa2);
}

void CaptureStorage::startAnalyzer() {
    if (not runAnalyzer) {
        runAnalyzer = true;
        pthread_create(&analyzerThread, NULL, analyzerThread_wrapper, static_cast<void *>(this));
    }
}

void CaptureStorage::stopAnalyzer() {
    runAnalyzer = false;
    pthread_join(analyzerThread, NULL);
}

std::list<NetStats> CaptureStorage::getNetStats() const {
    std::list<NetStats> result;
    for (std::map<NetID, NetInfo>::const_iterator net = nets.begin(); net != nets.end(); ++net) {
        NetStats ns = net->second.getStats();
        memcpy(ns.bssid, net->first.getBSSID(), sizeof(ns.bssid));
        ns.ssid = net->first.getSSID();
        result.push_back(ns);
    }
    return result;
}

std::list<NetStats> CaptureStorage::getNetStats(unsigned short channel) const {
    std::list<NetStats> result;
    
    std::map<unsigned short, std::list<NetID> >::const_iterator mapIter = netsByChannel.find(channel);
    if (mapIter != netsByChannel.end()) {
        for(std::list<NetID>::const_iterator net = mapIter->second.begin(); net !=  mapIter->second.end(); ++net) {
            std::map<NetID, NetInfo>::const_iterator netIter = nets.find(*net);
            if (netIter != nets.end()) {
                NetStats ns = netIter->second.getStats();
                memcpy(ns.bssid, netIter->first.getBSSID(), sizeof(ns.bssid));
                ns.ssid = netIter->first.getSSID();
                result.push_back(ns);
            }
        }
    }
    return result;
}

void CaptureStorage::analyzerThread_func() {
    std::list<NetID>* netsInChannel = NULL;
    unsigned short analyzerChannel = 0;
    
    if (channel != 0) netsInChannel = &netsByChannel[channel];
    
    while(runAnalyzer) {
        if (channel != analyzerChannel) { // When we detect a change of channel we delete the beacons of the old channel
            if (netsInChannel != NULL) {
                for(std::list<NetID>::const_iterator net = netsInChannel->begin(); net != netsInChannel->end(); ++net) {
                    nets[*net].restartStats();
                }
            }
            analyzerChannel = channel;
            netsInChannel = &netsByChannel[analyzerChannel];
        }
        
        if (netsInChannel != NULL) {
            for(std::list<NetID>::const_iterator net = netsInChannel->begin(); net != netsInChannel->end(); ++net) {
                nets[*net].calculateStats(TIMETODISCARD, analyzerSleepTime);
            }
            notifyChannelUpdate(analyzerChannel);
        }
        
        sleep(analyzerSleepTime);
    }
}

void* CaptureStorage::analyzerThread_wrapper(void* param) {
    static_cast<CaptureStorage *>(param)->analyzerThread_func();
    pthread_exit(NULL);
}

void CaptureStorage::notifyChannelUpdate(unsigned short channel) {
    std::list<NetStats> stats = getNetStats(channel);
    GUIEventDispatcher::registerEvent(new UpdateChannelEvent(channel, stats));
}

