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

#ifndef NETMANAGER_H
#define NETMANAGER_H

#include "CaptureStorage.h"
#include <string>
#include <list>
#include <vector>
#include <pthread.h>
#include <pcap.h>

/**
 * Class that controls a network monitor interface capturing her beacon
 * packets and changing the channel.
 * All the packets are send to a CaptureStorage that analyze the data
 * and computes the statistics.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class NetManager {
public:
    static const unsigned int DEFAULTCHANNELTIME = 8;        ///< Default value of channelTime
    static const unsigned int DEFAULTEMPTYCHANNELTIME = 1;   ///< Default value of channelEmptyTime

    /**
     * Constructor that creates a monitor interface calling createMonitorInterface()
     *
     * @param interface The interface identifier to use for create the monitor interface
     */
    NetManager(const std::string& interface);
    
    /**
     * Destructor.
     */
    virtual ~NetManager();
    
    /**
     * Gets the interface with that the NetManager was created.
     *
     * @return Interface name
     */
    std::string getInterface() const;
    
    /**
     * Creates a virtual monitor interface from another interface and set the NetManager
     * instnace to work with him.
     * removeMonitorInterface() is called before creating the new interface if an interface
     * was already created.
     *
     * @param interface The interface identifier to use for create the monitor interface
     * @return If a new virtual monitor interface have been created
     */
    bool createMonitorInterface(const std::string& interface);
    
    /**
     * Deletes the monInterface virtual monitor interface.
     */
    void removeMonitorInterface();
    
    /**
     * Check if a monitor interface was set.
     *
     * @return If a monitor interface was set
     */
    bool isMonitorInterfaceCreated() const;
    
    /**
     * Set channels.
     *
     * @param channels Vector with channel numbers
     */
    void setChannels(const std::list<unsigned short>& channels);
    
    /**
     * Add a channel to the network manager.
     *
     * @param channel Channel
     */
    void addChannel(unsigned short channel);
    
    /**
     * Locks the program into a channel
     *
     * @param channel Channel
     */
    void lockChannel(unsigned short channel);
    
    /**
     * Removes a channel of the network manager.
     *
     * @param channel Channel
     */
    void removeChannel(unsigned short channel);
    
    /**
     * Get channels.
     *
     * @return Channels list
     */
     std::list<unsigned short> getChannels() const;
    
    /**
     * Set channelTime.
     *
     * @param seconds Seconds that the channel controller will spend in a channel
     */
    void setChannelTime(unsigned int seconds);
    
    /**
     * Get channelTime.
     *
     * @returns Seconds that the channel controller will spend in a channel
     */
    unsigned int getChannelTime() const;
    
    /**
     * Set channelEmptyTime.
     *
     * @param seconds Seconds that the channel controller will spend in a channel without capture any packet
     */
    void setEmptyChannelTime(unsigned int seconds);
    
    /**
     * Get channelEmptyTime.
     *
     * @returns Seconds that the channel controller will spend in a channel without capture any packet
     */
    unsigned int getEmptyChannelTime() const;
    
    /**
     * Start the monitoring of the interface monInterface: start the controller
     * and the capture thread.
     *
     * @return Start monitoring correctly
     */
    bool startMonitoring();
    
    /**
     * Stop the monitoring of the interface monInterface: stop the controller,
     * the capture thread and the analyzer of the storage attribute calling CaptureStorage::stopAnalyzer().
     */
    void stopMonitoring();
    
    /**
     * Get a list with all the 802.11 network interfaces.
     *
     * @return Vector with the identifiers of the 802.11 network interfaces detected
     */
    static std::vector<std::string> list80211Interfaces();
    
private:
    static const unsigned short DEFAULTCHANNELS[];  ///< Contains the default channels of a NetManager (if not modified by setChannels())
    static const unsigned int TIMEOUT = 5000;       ///< PCAP packet timeout in miliseconds
    
    std::list<unsigned short> channels;   ///< List with the channels that will be used by the NetManager
    unsigned int channelTime;             ///< Time, in seconds, that the channel controller will spend in a channel
    unsigned int emptyChannelTime;        ///< Time, in seconds, that the channel controller will spend in a channel without capture any packet
    std::string interface;                ///< Creation interface
    std::string monInterface;             ///< Monitor interface identifier used by the NetManager

    CaptureStorage storage;               ///< Structure where store and analyze the packets
    bool controllerThreadRunning;         ///< Indicates if controllerThread is running
    pthread_t controllerThread;           ///< Structure of the controller thread
    pthread_t captureThread;              ///< Structure of the capture thread
    pthread_mutex_t channelMutex;         ///< Channels list mutex
    pcap_t *captureHandler;               ///< PCAP capture structure
    bool runController;                   ///< Indicates that the controller thread can be running
    unsigned int packets;                 ///< Number of captured packets on the current channel
    std::list<unsigned short>::iterator channelIt;        ///< Index of the current selected channel on the channels vector
    std::list<unsigned short>::iterator currentChannelIt; ///< Index of the current established channel on the channels vector
    
    /**
     * Do a change channel in the monitor interface.
     *
     * @param channel Channel to set
     * @return Correct change channel
     */
    bool changeChannel(unsigned short channel) const;
    
    /**
     * Try to set a channel of the channels vector in the monitor interface.
     *
     * @return Can set a channel
     */
    bool tryToSetAChannel();
    
    /**
     * Try to set the next channel of the channels vector in the monitor interface.
     * Update currentChannelIndex if the change channel is correct.
     * Always update the channelIndex value.
     *
     * @return Correct change channel
     */
    bool setNextChannel();
    
    /**
     * Get the current channel.
     *
     * @return Current channel number: channels[currentChannelIndex]
     */
    unsigned short getChannel();

    /**
     * Creates a virtual monitor interface from another interface.
     *
     * @param interface The interface identifier to use for create the monitor interface
     * @return The new monitor interface identifier. An empty string if error
     */
    static std::string newMonitorInterface(const std::string& interface);
    
    /**
     * Deletes a virtual monitor interface.
     *
     * @param interface The interface identifier
     */
    static void deleteMonitorInterface(const std::string& interface);
    
    
    /**
     * Launchs the controller thread if runController is true and controllerThreadRunning is false.
     */
    void launchControllerThread();
    
    /**
     * Static wrapper to the controllerThread_func() method of the "param" NetManager instance.
     *
     * @param param Pointer to a instance of NetManager (typically "this")
     * @return pthread_exit(NULL)
     */
    static void* controllerThread_wrapper(void* param);
    
    /**
     * Method that controles the change channels while runController is true and
     * channels have more than one element (channels.size() > 1)
     */
    void controllerThread_func();
    
    /**
     * Static wrapper to the captureThread_func() method of the "param" NetManager instance.
     *
     * @param param Pointer to a instance of NetManager (typically "this")
     * @return pthread_exit(NULL)
     */
    static void* captureThread_wrapper(void* param);
    
    /**
     * Method that invokes pcap_loop() with the gotPacket() method.
     * The method returns the control when pcap_breakloop() is invoked.
     */
    void captureThread_func();
    
    /**
     * Method used by pcap_loop() to handle the captured packets.
     *
     * @param args Arguments passed to the pcap_loop() function
     * @param header PCAP Packet header with information
     * @param packet Captured data
     * @see http://www.tcpdump.org/pcap3_man.html
     */
    static void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
    
    /**
     * Notifies to the GUIs a change channel.
     *
     * @param channel Channel
     */
    void notifyChangeScanChannel(unsigned short channel);
};

#endif
