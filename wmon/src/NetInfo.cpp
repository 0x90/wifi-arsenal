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

#include "NetInfo.h"
#include <ctime>

std::list<const NetInfo*> NetInfo::locks;
pthread_mutex_t NetInfo::mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t NetInfo::condVar = PTHREAD_COND_INITIALIZER;

NetInfo::NetInfo()
    : delay(0), lastDelay(0), lost(0), weightedDelay(0), rssi(0), ok(false), maxPackets(0), security(OPEN), timeOK(0), bestIndex(-1) {}

unsigned int NetInfo::getInterval() const {
    return interval;
}

void NetInfo::setInterval(unsigned int interval) {
    this->interval = interval;
}

unsigned short NetInfo::getChannel() const {
    return channel;
}

void NetInfo::setChannel(unsigned short channel) {
    this->channel = channel;
}

void NetInfo::setSecurity(Security sec) {
    if (security < sec) security = sec;
}

void NetInfo::setWEP(bool wepDetected) {
    if (wepDetected) setSecurity(WEP);
}

void NetInfo::setWPA(bool wpaDetected) {
    if (wpaDetected) setSecurity(WPA);
}

void NetInfo::setWPA2(bool wpa2Detected) {
    if (wpa2Detected) setSecurity(WPA2);
}

bool NetInfo::hasLock(const NetInfo* ni) {
    for (std::list<const NetInfo*>::const_iterator iter = locks.begin(); iter != locks.end(); ++iter) {
        if (*iter == ni) return true;
    }
    return false;
}

void NetInfo::adquireLock(const NetInfo* ni) {
    pthread_mutex_lock(&mutex);
    while (hasLock(ni)) pthread_cond_wait(&condVar, &mutex);
    locks.push_back(ni);
    pthread_mutex_unlock(&mutex);
}

void NetInfo::releaseLock(const NetInfo* ni) {
    pthread_mutex_lock(&mutex);
    locks.remove(ni);
    pthread_cond_broadcast(&condVar);
    pthread_mutex_unlock(&mutex);
}

void NetInfo::calculateStats(unsigned int timeToDiscard, unsigned int analyzerSleepTime) {
    adquireLock(this);
    this->maxPackets = timeToDiscard*SECtoMICROSEC/interval;
    
    if (not beacons.empty()) {
        if ((lastDelay != 0 or timeOK < timeToDiscard) and bestIndex >= 0) {
            numPackets = beacons.size();
            if (not calculateStats(false) and lastDelay < 0.8) timeOK = 0;
            else if (timeOK < timeToDiscard) timeOK += analyzerSleepTime;
        }
        removeOldBeacons(timeToDiscard);
        selectBest();
        calculateStats(true);
        statsTimestamp = time(NULL);
        ok = timeOK >= timeToDiscard;
    }
    
    releaseLock(this);
}

void NetInfo::addBeaconInfo(const BeaconInfo& beacon) {
    adquireLock(this);
    beacons.push_back(beacon);
    releaseLock(this);
}

NetStats NetInfo::getStats() const {
    NetStats stats;
    stats.statsTimestamp = statsTimestamp;
    stats.channel = channel;
    
    switch (security) {
        case OPEN: stats.protection = "Open"; break;
        case WEP:  stats.protection = "WEP";  break;
        case WPA:  stats.protection = "WPA";  break;
        case WPA2: stats.protection = "WPA2"; break;
        default:   stats.protection = "Unknown";
    }
    
    stats.delay = delay;
    stats.loss = lost;
    stats.weightedDelay = weightedDelay;
    stats.rssi = rssi;
    stats.ok = ok;
    return stats;
}

void NetInfo::restartStats() {
    adquireLock(this);
    restartStatsNoLock();
    releaseLock(this);
}

void NetInfo::restartStatsNoLock() {
    beacons.clear();
    lastDelay = 0;
    timeOK = 0;
    bestIndex = -1;
}

unsigned int NetInfo::lossPackets(long int diffTimestamp, int beaconInterval) {
    return (diffTimestamp - beaconInterval/2)/beaconInterval - ((diffTimestamp - beaconInterval/2)%beaconInterval == 0);
}

bool NetInfo::calculateStats(bool stats) {
    //If we don't have any packet we restart the stats.
    if(numPackets == 0) {
        if(stats) {
            delay = 1.0;
            weightedDelay = 1.0;
            lost = 1.0;
            ok = false;
        }
        restartStatsNoLock();
        return false;
    }
    
    bool error = false;
    int delayed = 0;
    int sumRSSI = 0;
    unsigned int packetsWithRSSI = 0;
    if (best->hasRSSI) {
        ++packetsWithRSSI;
        sumRSSI = best->rssi;
    }
    
    unsigned int lossLeft = 0;
    std::list<BeaconInfo>::const_iterator packet = best;
    std::list<BeaconInfo>::const_iterator lastPacket = packet--;
    
    for (int i = bestIndex - 1; not error and i >= 0; --i, --packet, --lastPacket) {
        long int thi = lastPacket->sec - packet->sec;
        long int tlo = thi*SECtoMICROSEC + lastPacket->usec - packet->usec;
        lossLeft += lossPackets(tlo, packet->interval);
        int dn = packet->timestamp - best->timestamp - packet->interval*(i - bestIndex - lossLeft);
        
        if (packet->hasRSSI) {
            ++packetsWithRSSI;
            sumRSSI += packet->rssi;
        }
        
        if (dn > DELAY) ++delayed;
        else if (dn < -DELAY) error = true;
    }
    
    unsigned int lossRight = 0;
    packet = best;
    lastPacket = packet++;
    
    for (int i = bestIndex + 1; not error and i < numPackets; ++i, ++packet, ++lastPacket) {
        long int thi = packet->sec - lastPacket->sec;
        long int tlo = thi*SECtoMICROSEC + packet->usec - lastPacket->usec;
        lossRight += lossPackets(tlo, packet->interval);
        int dn = packet->timestamp - best->timestamp - packet->interval*(i - bestIndex + lossRight);
        
        if (packet->hasRSSI) {
            ++packetsWithRSSI;
            sumRSSI += packet->rssi;
        }
        
        if (dn > DELAY) ++delayed;
        else if (dn < -DELAY) error = true;
    }
    
    if (stats) {
        unsigned int lossPackets = lossLeft + lossRight; // It only calculates the lost packets between the first and last packet used on the calculation.
        unsigned int totalPackets = numPackets + lossPackets; // Total packets between the first and last packet used on the calculation.
        
        double max = double(maxPackets);
        if (max < totalPackets) max = totalPackets; // For safeguard
        
        double tDelayedMin = delayed/max; // Suppose all lost packets like not delayed packets: only delayed variable are delayed packets.
        double tDelayedMax = (delayed + max - numPackets)/max; // Suppose all lost packets like delayed packets: delayed variable + all lost packets are delayed.
        lastDelay = delay = (tDelayedMin + tDelayedMax)/2; // First metric: Average of tDelayedMin and tDelayedMax
        
        double tDelayedCalculated = double(delayed)/numPackets; // Calculate the % of packets delayed from the number of packets captured
        weightedDelay = tDelayedCalculated*tDelayedMax + (1 - tDelayedCalculated)*tDelayedMin; // Second metric: Weight the delays with the tDelayedCalculated %
        
        lost = (max - numPackets)/max; // Lost packets is computed by the maximum number of packets (usually maxPackets) - captured packets
        
        if (packetsWithRSSI > 0) rssi = sumRSSI/int(packetsWithRSSI);
    }
    return not error;
}

void NetInfo::selectBest() {
    bestIndex = 0;
    int dnBest = 0;
    unsigned int loss = 0;
    std::list<BeaconInfo>::const_iterator bestPacket = beacons.begin();
    std::list<BeaconInfo>::const_iterator packet = beacons.begin();
    std::list<BeaconInfo>::const_iterator lastPacket = packet++;
    long long t0 = bestPacket->timestamp;
    for (unsigned int i = 1; i < numPackets; ++i, ++packet, ++lastPacket) {
        long int thi = packet->sec - lastPacket->sec;
        long int tlo = thi*SECtoMICROSEC + packet->usec - lastPacket->usec;
        loss += lossPackets(tlo, packet->interval);
        int dn = packet->timestamp - t0 - packet->interval*(i + loss);
        
        if (dn < dnBest) {
            bestIndex = i;
            dnBest = dn;
            bestPacket = packet;
        }
    }

    best = bestPacket;
}

void NetInfo::removeOldBeacons(unsigned int sec) {
    std::list<BeaconInfo>::const_reverse_iterator lastPacket = beacons.rbegin();
    time_t actualSec = time(NULL);
    time_t minTime = actualSec - sec; // We delete all packets that are older than sec seconds
    
    while (not beacons.empty() and beacons.front().sec < minTime) beacons.pop_front();
    
    if (lastPacket->sec == actualSec) {
        while (not beacons.empty() and beacons.front().sec == minTime and beacons.front().usec <= lastPacket->usec)
            beacons.pop_front();
    }
    
    numPackets = 0;
    if (not beacons.empty())
        for (std::list<BeaconInfo>::const_iterator packet = beacons.begin(); &*packet != &*lastPacket; ++packet, ++numPackets);
}

