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

#ifndef NETID_H
#define NETID_H

#include <stdint.h>
#include <ostream>
#include <string>

/**
 * Class that represents a network identifier.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class NetID {
public:

    /**
     * Constructor with parameter initialization.
     *
     * @param bssid Byte array with the network BSSID
     * @param ssid String with the network SSID
     */
    NetID(const uint8_t bssid[6], const char ssid[]);
    
    /**
     * Set the network BSSID.
     *
     * @param bssid Byte array with the network BSSID
     */
    void setBSSID(const uint8_t bssid[6]);
    
    /**
     * Get the stored network BSSID.
     *
     * @return Stored network BSSID
     */
    const uint8_t* getBSSID() const;
    
    /**
     * Set the network SSID.
     *
     * @param ssid String with the network SSID
     */
    void setSSID(const char ssid[]);
    
    /**
     * Get the stored network SSID.
     *
     * @return Stored network SSID
     */
    std::string getSSID() const;
    
    /**
     * Overload compare operator: less than.
     *
     * @param n Object to compare
     * @return this is less than n
     */
    bool operator < (const NetID &n) const;
    
    /**
     * Overload compare operator: equal than.
     *
     * @param n Object to compare
     * @return this is equal than n
     */
    bool operator == (const NetID &n) const;
    
    /**
     * Overload assignation operator.
     *
     * @param n Object to assign
     * @return Reference to this
     */
    const NetID& operator = (const NetID &n);

private:
    uint8_t bssid[6]; ///< Network BSSID
    std::string ssid; ///< Network SSID
};

#endif
