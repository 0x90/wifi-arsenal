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

#ifdef QTGUI
#include <iostream>
using namespace std;
#endif

#include "NetManager.h"
#include "AirmonNG.h"
#include "GUIEventDispatcher.h"
#include "RemainingChannelTimeEvent.h"
#include "ChangeChannelEvent.h"
#include <iwlib.h>
#include <sstream>
#include <algorithm>

const unsigned short NetManager::DEFAULTCHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

NetManager::NetManager(const std::string& interface) {
    pthread_mutex_init(&channelMutex, NULL);
    this->interface = interface;
    createMonitorInterface(interface);
    channelTime = DEFAULTCHANNELTIME;
    emptyChannelTime = DEFAULTEMPTYCHANNELTIME;
    runController = false;
    controllerThreadRunning = false;
    packets = 0;
    captureHandler = NULL;
    setChannels(std::list<unsigned short>(DEFAULTCHANNELS, DEFAULTCHANNELS + sizeof(DEFAULTCHANNELS)/sizeof(unsigned short)));
}

NetManager::~NetManager() {
    // stopMonitoring();
    removeMonitorInterface();
    pthread_mutex_destroy(&channelMutex);
}

std::string NetManager::getInterface() const {
    return interface;
}

bool NetManager::createMonitorInterface(const std::string& interface) {
    bool backupRunController = runController;
    if (isMonitorInterfaceCreated()) removeMonitorInterface();
    monInterface = newMonitorInterface(interface);
    if (isMonitorInterfaceCreated() and backupRunController) {
        #ifdef QTGUI
        cout << "NetManager: Start monitoring" << endl;
        #endif
        storage.startAnalyzer();
        startMonitoring();
    }
    #ifdef QTGUI
    else cout << "NetManager: Don't start monitoring" << endl;
    #endif
    return isMonitorInterfaceCreated();
}

void NetManager::removeMonitorInterface() {
    if (isMonitorInterfaceCreated()) {
        stopMonitoring();
        deleteMonitorInterface(monInterface);
        monInterface.clear();
    }
}

bool NetManager::isMonitorInterfaceCreated() const {
    return not monInterface.empty();
}

void NetManager::setChannels(const std::list<unsigned short>& channels) {
    pthread_mutex_lock(&channelMutex);
    this->channels = channels;
    this->channels.sort();
    this->channelIt = this->channels.end();
    this->currentChannelIt = this->channelIt--;
    pthread_mutex_unlock(&channelMutex);
    
    launchControllerThread();
}

std::list<unsigned short> NetManager::getChannels() const {
    return channels;
}

void NetManager::addChannel(unsigned short channel) {
    pthread_mutex_lock(&channelMutex);
    std::list<unsigned short>::iterator it = channels.begin();
    while (it != channels.end() and *it < channel) ++it;
    channels.insert(it, channel);
    
    if (channels.size() == 1) channelIt = this->channels.end();
    
    pthread_mutex_unlock(&channelMutex);
    
    launchControllerThread();
}

void NetManager::removeChannel(unsigned short channel) {
    pthread_mutex_lock(&channelMutex);
    bool lock = true;
    std::list<unsigned short>::iterator it = find(channels.begin(), channels.end(), channel);
    
    if (it != channels.end()) {
        bool currentChannel = it == currentChannelIt;
        if (currentChannel) ++currentChannelIt;
        if (it == channelIt and ++channelIt == channels.end()) channelIt = channels.begin();
        channels.erase(it);
        if (currentChannel) {
            lock = false;
            pthread_mutex_unlock(&channelMutex);
            if (tryToSetAChannel()) notifyChangeScanChannel(getChannel());
        }
    }
    if (lock) pthread_mutex_unlock(&channelMutex);
}

void NetManager::lockChannel(unsigned short channel) {
    pthread_mutex_lock(&channelMutex);
    std::list<unsigned short>::iterator it = find(channels.begin(), channels.end(), channel);
    
    if (it != currentChannelIt) {
        if (changeChannel(channel)) {
            runController = false;
            currentChannelIt = it;
            notifyChangeScanChannel(channel);
        }
    }
    else runController = not runController;
    
    launchControllerThread();
    
    pthread_mutex_unlock(&channelMutex);
}

void NetManager::launchControllerThread() {
    if (runController and not controllerThreadRunning) {
        pthread_create(&controllerThread, NULL, controllerThread_wrapper, static_cast<void *>(this));
    }
}

void NetManager::setChannelTime(unsigned int seconds) {
    channelTime = seconds;
}

unsigned int NetManager::getChannelTime() const {
    return channelTime;
}

void NetManager::setEmptyChannelTime(unsigned int seconds) {
    emptyChannelTime = seconds;
}

unsigned int NetManager::getEmptyChannelTime() const {
    return emptyChannelTime;
}

bool NetManager::startMonitoring() {
    if (not isMonitorInterfaceCreated()) return false;
    if (captureHandler != NULL) return false;
    
    // Opens the pcap capturer handler
    char errbuf[PCAP_ERRBUF_SIZE];
    captureHandler = pcap_open_live(monInterface.c_str(), BUFSIZ, 1, TIMEOUT, errbuf);
    if (captureHandler == NULL) return false;

    // Only capture beacons
    struct bpf_program filter;
    if (pcap_compile(captureHandler, &filter, "link[0] == 0x80", 0, 0) < 0) return false;
    if (pcap_setfilter(captureHandler, &filter) < 0) return false;
    
    // Creates the controller and capture threads
    runController = true;
    launchControllerThread();
    pthread_create(&captureThread, NULL, captureThread_wrapper, static_cast<void *>(this));

    return true;
}

void NetManager::stopMonitoring() {
    if (captureHandler == NULL) return;
    
    // Breaks the capturer
    runController = false;
    pcap_breakloop(captureHandler);
    
    storage.stopAnalyzer();
    
    pthread_join(controllerThread, NULL);
    pthread_join(captureThread, NULL);
    
    pcap_close(captureHandler);
    captureHandler = NULL;
}

static int enum_devices_callback_get80211(int skfd, char* ifname, char** args, int /*count*/) {
    struct wireless_info info;
    if (iw_get_basic_config(skfd, ifname, &(info.b)) >= 0) {
        reinterpret_cast<std::vector<std::string> *>(args)->push_back(std::string(ifname));
    }
    return 0;
}

std::vector<std::string> NetManager::list80211Interfaces() {
    std::vector<std::string> interfaces;
    int skfd = iw_sockets_open();
    iw_enum_devices(skfd, enum_devices_callback_get80211, reinterpret_cast<char**>(&interfaces), 0);
    return interfaces;
}

bool NetManager::changeChannel(unsigned short channel) const {
    std::stringstream ss;
    ss << "iwconfig " << monInterface << " channel " << channel << " > /dev/null 2> /dev/null";
    if (system(ss.str().c_str()) != 0) return false;
    return true;
}

bool NetManager::tryToSetAChannel() {
    std::list<unsigned short>::iterator startIndex = channelIt;
    do {
        if (setNextChannel()) return true;
    } while (channelIt != startIndex);
    return false;
}

bool NetManager::setNextChannel() {
    pthread_mutex_lock(&channelMutex);
    
    bool res = false;
    if (runController and not channels.empty()) {
        if (++channelIt == channels.end()) channelIt = channels.begin();
        
        if (changeChannel(*channelIt)) {
            #ifdef QTGUI
            cout << "NetManager: Selected channel -> " << *channelIt << endl;
            #endif
            currentChannelIt = channelIt;
            res = true;
        }
    }
    pthread_mutex_unlock(&channelMutex);
    
    return res;
}

unsigned short NetManager::getChannel() {
    pthread_mutex_lock(&channelMutex);
    unsigned short res = *currentChannelIt;
    pthread_mutex_unlock(&channelMutex);
    return res;
}

std::string NetManager::newMonitorInterface(const std::string& interface) {
    return AirmonNG::createMonitorInterface(interface);
}

void NetManager::deleteMonitorInterface(const std::string& interface) {
    AirmonNG::deleteMonitorInterface(interface);
}

void* NetManager::controllerThread_wrapper(void *param) {
    #ifdef QTGUI
    cout << "NetManager: Starting controller thread" << endl;
    #endif

    static_cast<NetManager *>(param)->controllerThreadRunning = true;
    static_cast<NetManager *>(param)->controllerThread_func();
    static_cast<NetManager *>(param)->controllerThreadRunning = false;

    #ifdef QTGUI
    cout << "NetManager: Stopping controller thread" << endl;
    #endif
    pthread_exit(NULL);
}

void NetManager::controllerThread_func() {
    while (runController and channels.size() > 1) {
        if (setNextChannel()) {
            packets = 0;
            notifyChangeScanChannel(getChannel());
            for (int i = emptyChannelTime; runController and i > 0; --i) {
                GUIEventDispatcher::registerEvent(new RemainingChannelTimeEvent(channelTime - emptyChannelTime + i));
                sleep(1);
            }
            if (packets > 0) {
                for (int i = channelTime - emptyChannelTime; runController and i > 0; --i) {
                    GUIEventDispatcher::registerEvent(new RemainingChannelTimeEvent(i));
                    sleep(1);
                }
            }
        }
        // else signal error
    }
    
    GUIEventDispatcher::registerEvent(new RemainingChannelTimeEvent(-1)); // -1 (< 0) is a key value to indicate that the controller thread is stopped
    
    if (runController and channels.size() == 1 and tryToSetAChannel()) notifyChangeScanChannel(getChannel());
}
    
void* NetManager::captureThread_wrapper(void *param) {
    static_cast<NetManager *>(param)->captureThread_func();
    pthread_exit(NULL);
}

void NetManager::gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    ++reinterpret_cast<NetManager *>(args)->packets;
    reinterpret_cast<NetManager *>(args)->storage.addCapture(packet, header->caplen, header->ts.tv_sec, header->ts.tv_usec);
}

void NetManager::captureThread_func() {
    pcap_loop(captureHandler, -1, gotPacket, (u_char*) this);
}

void NetManager::notifyChangeScanChannel(unsigned short channel) {
    storage.setChannel(channel);
    GUIEventDispatcher::registerEvent(new ChangeChannelEvent(channel));
}

