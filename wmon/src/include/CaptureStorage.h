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

#ifndef CAPTURESTORAGE_H
#define CAPTURESTORAGE_H

#include "NetID.h"
#include "NetInfo.h"
#include "BeaconInfo.h"
#include "NetStats.h"
#include <map>
#include <list>

/**
 * Store networks and beacons information, providing a thread to analyze
 * this information to generate statistics.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class CaptureStorage {
public:

    /** Constructor */
    CaptureStorage();
    
    /** Destructor */
    ~CaptureStorage();
    
    /**
     * Add a beacon capture.
     *
     * @param packet Pointer to the packet
     * @param len Length of the packet
     * @param sec Second when the packet was captured
     * @param usec Microsecond when the packet was captured
     */
    void addCapture(const unsigned char *packet, unsigned int len, long int sec, long int usecs);
    
    /**
     *  Start the analyzer thread.
     */
    void startAnalyzer();
    
    /**
     * Stop the analyzer thread.
     */
    void stopAnalyzer();
    
    /**
     * Sets the current channel.
     *
     * @param channel Channel number
     */
    void setChannel(unsigned short channel);
    
    /**
     * Obtain the statistics of all the networks detected.
     *
     * @return Statistics of all the networks detected
     */
    std::list<NetStats> getNetStats() const;
    
    /**
     * Obtain the statistics of the networks of a channel.
     *
     * @param channel Channel to get the statistics
     * @return Statistics of the indicated channel networks
     */
    std::list<NetStats> getNetStats(unsigned short channel) const;

private:
    static const unsigned int TIMETODISCARD = 5;        ///< Time, in seconds, that is used to compute the stats (use the last TIMETODISCARD seconds of beacons)
    static const unsigned int analyzerSleepTime = 1;    ///< Time that the analyzer thread sleep after check if runAnalyzer is true or compute the stats.

    std::map<unsigned short, std::list<NetID> > netsByChannel; ///< Map with a correlation channel-list of networks identifiers (NetID)
    std::map<NetID, NetInfo> nets;  ///< Structure that contains the networks information
    pthread_t analyzerThread;       ///< Structure of the analyzer thread
    
    bool runAnalyzer;               ///< Indicates that the analyzer thread has to be running
    unsigned short channel;         ///< Channel of the last captured packet
    
    /**
     * Method that computes the networks stats of the current channel (in "channel" attribute)
     * every second, calling notifyChannelUpdate(), while runAnalyzer is true.
     * When the method detects a channel change, it clears the information from previous channel networks (calls NetInfo::restartStats())
     */
    void analyzerThread_func();
    
    /**
     * Static wrapper to the analyzerThread_func() method of the "param" CaptureStorage instance.
     *
     * @param param Pointer to a instance of CaptureStorage (typically "this")
     * @return pthread_exit(NULL)
     */
    static void* analyzerThread_wrapper(void* param);
    
    /**
     * Register a UpdateChannelEvent in the GUIEventDispatcher with the stats information of
     * the indicated channel networks.
     *
     * @param channel Channel to notify the update of stats
     */
    void notifyChannelUpdate(unsigned short channel);
};

#endif
