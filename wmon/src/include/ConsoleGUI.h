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

#ifndef CONSOLEGUI_H
#define CONSOLEGUI_H

#include "GUI.h"
#include <ncurses.h>
#include <pthread.h>

/**
 * Provides a console GUI with ncurses.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class ConsoleGUI : public GUI {
public:

    /**
     * Constructor. Draws the main window.
     */
    ConsoleGUI();
    
    /**
     * Destructor. Cleans the window and returns it to their original state.
     */
    ~ConsoleGUI();
    
    /**
     * Start the GUI loop reading the keys to modify the GUI behavior.
     */
    void loop();
    
    /**
     * Notifies the updated stats of the networks of a channel.
     *
     * @param channel Channel of the update notification
     * @param stats NetStats with the updated information
     */
    void updateChannel(unsigned short channel, const std::list<NetStats>& stats);
    
    /**
     * Notifies a change of channel
     *
     * @param channel Channel number that will be notified
     */
    void updateScanChannel(unsigned short channel);
    
    /**
     * Notifies the remainin time on the channel.
     *
     * @param seconds Seconds left on the channel
     */
    void updateRemainingChannelTime(int seconds);
    
private:
    static const unsigned int FIRSTSORTLETTER = 20; ///< Column where starts the list of sort options
    
    static const char SORTKEYLOSSBOTTOM  = 'P'; ///< Key assigned to list the networks with 100% of loss at the bottom
    static const char SORTKEYBSSID       = 'B'; ///< Key assigned to sort by BSSID
    static const char SORTKEYCHANNEL     = 'C'; ///< Key assigned to sort by channel
    static const char SORTKEYUTILIZATION = 'U'; ///< Key assigned to sort by utilization
    static const char SORTKEYLOSS        = 'L'; ///< Key assigned to sort by loss
    static const char SORTKEYRSSI        = 'R'; ///< Key assigned to sort by RSSI
    static const char SORTKEYSSID        = 'S'; ///< Key assigned to sort by SSID
    
    static bool (*sortMethod)(const NetStats& i, const NetStats& j); ///< Pointer to the sort method
    static bool disappearedAtBottom; ///< List the networks with 100% loss at the bottom
    
    WINDOW* main;               ///< Structure of the main window
    WINDOW* listNetworks;       ///< Structure that represents the area to draw the list of networks
    pthread_mutex_t guiMutex;   ///< Mutex for the GUI elements and channel attribute
    pthread_mutex_t dataMutex;  ///< Mutex for the stats attribute
    int nrows;          ///< Number of rows of the window
    int ncols;          ///< Number of columns of the window
    int currentIndex;   ///< Actual index of scrolling
    
    std::list<NetStats> stats; ///< Structure that stores the networks information
    unsigned short channel; ///< Stores the current channel
    
    /**
     * Inicialize the console GUI drawing the interface.
     */
    void initScreen();
    
    /**
     * Executes the needed actions to do a console resize.
     */
    void doResize();
    
    /**
     * Draw the main window.
     *
     * This method has not mutex control and uses main WINDOW attribute.
     */
    void drawMainWindow();
    
    /**
     * Print current channel.
     *
     * This method has not mutex control and uses main WINDOW attribute.
     */
    void printChannel();
    
    /**
     * Print the sort keys.
     *
     * This method has not mutex control and uses main WINDOW attribute.
     */
    void printSortKeys();
    
    /**
     * Prints a character in a coordinate of a WINDOW.
     *
     * @param window WINDOW structure to print the character
     * @param y Vertical coordinate
     * @param x Horizontal coordinate
     * @param ch Character to print
     * @param reverse Print in reverse mode
     */
    static void printChar(WINDOW* window, int y, int x, char ch, bool reverse);
    
    /**
     * Draw the list of networks stats.
     *
     * This method has not mutex control, reads stats attribute and uses listNetworks WINDOW.
     */
    void drawList();
    
    /**
     * Writes the a network stats on the screen.
     *
     * This method has not mutex control, reads stats attribute.
     *
     * @param net Network stats to write
     * @param line Line to write (start in 0)
     * @param lineSeparator Draw a line after the information?
     */
    void scrollWindow(int offset);  // No mutex. Read stats and call drawList.
    
    /**
     * Writes the a network stats on the screen.
     *
     * This method has not mutex control.
     *
     * @param net Network stats to write
     * @param line Line to write (start in 0)
     * @param lineSeparator Draw a line after the information?
     */
    void addNetwork(const NetStats& net, int line, bool lineSeparator);
    
    
    /* Sort methods */
    
    /**
     * The NetStats i goes before j according to:
     *     - If disappearedAtBottom is true and (loss of i == 1 XOR loss of j == 1) then
     *          Return the network that have loss != 1
     *
     *     - Otherwise return the value of call the function pointed by sortMethod attribute.
     *
     * @param i NetStats to compare
     * @param j NetStats to compare
     * @return i goes before j according the sort method selected in sortMethod and the value of disappearedAtBottom
     */
    static bool generalSort(const NetStats& i, const NetStats& j);
    
    /**
     * The NetStats i goes before j according their channel.
     * If both networks have the same channel it compares de BSSID.
     * If both networks have the same channel and BSSID it compares de SSID.
     *
     * @param i NetStats to compare
     * @param j NetStats to compare
     * @return The channel of i is less than the channel of j. if both attributes have and equal value it compares the BSSID and, finally, the SSID.
     */
    static bool sortByBSSID(const NetStats& i, const NetStats& j);
    
    /**
     * The NetStats i goes before j according their channel.
     *
     * @param i NetStats to compare
     * @param j NetStats to compare
     * @return The loss of i is less than the loss of j. If both attributes have an equal value the result is sortByChannel()
     */
    static bool sortByChannel(const NetStats& i, const NetStats& j);
    
    /**
     * The NetStats i goes before j according their utilization.
     *
     * @param i NetStats to compare
     * @param j NetStats to compare
     * @return The utilization of i is less than the utilization of j. If both attributes have an equal value the result is sortByChannel()
     */
    static bool sortByUtilization(const NetStats& i, const NetStats& j);
    
    /**
     * The NetStats i goes before j according their loss.
     *
     * @param i NetStats to compare
     * @param j NetStats to compare
     * @return The loss of i is less than the loss of j. If both attributes have an equal value the result is sortByChannel()
     */
    static bool sortByLoss(const NetStats& i, const NetStats& j);
    
    /**
     * The NetStats i goes before j according their RSSI.
     * If one of the networks have a 100% of loss the network goes afther the other.
     *
     * @param i NetStats to compare
     * @param j NetStats to compare
     * @return The RSSI of i is less than the RSSI of j. If both attributes have an equal value the result is sortByChannel()
     */
    static bool sortByRSSI(const NetStats& i, const NetStats& j);
    
    /**
     * The NetStats i goes before j according their SSID.
     *
     * @param i NetStats to compare
     * @param j NetStats to compare
     * @return The SSID of i is less than the SSID of j. If both attributes have an equal value the result is sortByChannel()
     */
    static bool sortBySSID(const NetStats& i, const NetStats& j);
};

#endif
