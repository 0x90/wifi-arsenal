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

#ifndef NETINFO_H
#define NETINFO_H

#include "BeaconInfo.h"
#include "NetStats.h"
#include <list>
#include <pthread.h>

/**
 * Class that contains dynamic information about a network and computes some statistics.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class NetInfo {
public:
    static const unsigned int SECtoMICROSEC = 1000000;  ///< Constant to convert seconds to microseconds
    static const int DELAY = 20;  ///< A packet is considered delayed after that time in microseconds
    
    /**
     * Constructor.
     */
    NetInfo();
    
    /**
     * Gets the beacon interval.
     */
    unsigned int getInterval() const;
    
    /**
     * Sets the becon interval.
     *
     * @param interval Beacon interval
     */
    void setInterval(unsigned int interval);
    
    /**
     * Gets the network channel.
     */
    unsigned short getChannel() const;
    
    /**
     * Sets the network channel.
     *
     * @param channel Channel
     */
    void setChannel(unsigned short channel);
    
    /**
     * Sets WEP protection detected.
     */
    void setWEP(bool wepDetected);
    
    /**
     * Sets WPA protection detected.
     */
    void setWPA(bool wpaDetected);
    
    /**
     * Sets WPA2 protection detected.
     */
    void setWPA2(bool wpa2Detected);
    
    /**
     * Compute the stats of the NetInfo.
     *
     * @param timeToDiscard Time to compute the stats in seconds (use only the last timeToDiscard seconds)
     * @param analyzerSleepTime Time that the analyzer sleeps
     */
    void calculateStats(unsigned int timeToDiscard, unsigned int analyzerSleepTime);
    
    /**
     * Add a BeaconInfo to the beacon list.
     *
     * @param beacon BeaconInfo to add
     */
    void addBeaconInfo(const BeaconInfo& beacon);
    
    /**
     * Obtain a NetStats structure with the current stats.
     *
     * @return NetStats with the current stats
     */
    NetStats getStats() const;
    
    /**
     * Thread safe version of restartStatsNoLock().
     * @see restartStatsNoLock()
     */
    void restartStats();

private:

    // NetDynInfo
    unsigned short channel; ///< Network channel
    unsigned int interval;  ///< Network beacon interval

    // NetStats
    time_t statsTimestamp;  ///< Timestamp of the stats
    
    double delay;           ///< Network beacon delay (assume that half of the lost packets are packets delayed)
    double lastDelay;       ///< Previous value of delay
    double lost;            ///< Network beacon loss ratio
    double weightedDelay;   ///< Network beacon delay (assume that the proportion of packets delayed of the lost packets are equal to the proportion of the packets delayed from packets captured)
    int rssi;               ///< Network RSSI
    bool ok;                ///< Reliability of this stats
    unsigned int maxPackets;///< Max packets that we expect to have according to the beacon interval and the calculate stats time (5 seconds of capture)

    enum Security {
        OPEN = 0,
        WEP,
        WPA,
        WPA2
    } security;

    std::list<BeaconInfo> beacons; ///< List of beacons

    // Control information
    unsigned int numPackets;    ///< Number of packets (<= beacons.size())
    unsigned int timeOK;        ///< Counter of times that we compute the statistics without errors
    int bestIndex;              ///< Index of the best packet (computed by selectBest())
    std::list<BeaconInfo>::const_iterator best; ///< Iterator of the best packet (computed by selectBest())
    
    // Mutex data
    static std::list<const NetInfo*> locks;      ///< Pointers to NetInfo with locks
    static pthread_mutex_t mutex;    ///< Mutex for concurrence control
    static pthread_cond_t condVar;   ///< Conditional variable for concurrence control
    
    /**
     * Set security level.
     *
     * @param sec Security level to set.
     */
    void setSecurity(Security sec);
    
    /**
     * Check if a NetInfo has a lock.
     *
     * @param ni Pointer to the NetInfo to check if has a lock
     * @return ni have a lock
     */
    static bool hasLock(const NetInfo* ni);
    
    /**
     * Adquire a lock for a NetInfo.
     *
     * @param ni Pointer to the NetInfo that requets the lock
     */
    static void adquireLock(const NetInfo* ni);
    
    /**
     * Release a lock of a NetInfo.
     *
     * @param ni Pointer to the NetInfo that releases the lock
     */
    static void releaseLock(const NetInfo* ni);
    
    /**
     * Removes all the stored beacons and restart the timeOK and lastDelay attribute.
     * The other attributes are not modified, if getStats() is called before calculateStats()
     * you will get the lastest calculated stats.
     */
    void restartStatsNoLock();
    
    /**
     * If stats is true then the statistics are computed and storerd in the variables
     *
     * Preconditions:
     *     this->numPackets is set with the number of packets to calculate stats AND
     *     this->best is the best packet to use as t0 AND
     *     this->bestIndex is the index of this->best in this->beacons
     *
     * @param stats Computes and stores the stats
     * @return No negative delays detected
     */
    bool calculateStats(bool stats);
    
    /**
     * this->best is the best packet to use as t0 and
     * this->bestIndex is the index of this->best in this->beacons
     *
     * Precondition: this->numPackets was set with the number of packets to calculate stats. 
     */
    void selectBest();
    
    /**
     * Removes all the BeaconInfo from this->beacons that have beacons[].sec < (actualTime - sec) and
     * set this->numPackets with the remaining number of packets
     *
     * @param sec Seconds (from now)
     */
    void removeOldBeacons(unsigned int sec);
    
    /**
     * Calculates the number of loss packets in a interval of time.
     * The function asumes that a packet is lost after 1.5*beaconInterval time units.
     * After that, every beaconInterval time units is computed like another loss packet.
     *
     * @param diffTimestamp Interval of time
     * @param beaconInterval Beacon innterval
     * @return Stimated loss packets
     */
    static inline unsigned int lossPackets(long int diffTimestamp, int beaconInterval);
};

#endif
