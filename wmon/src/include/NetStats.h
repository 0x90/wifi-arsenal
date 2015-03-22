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

#ifndef NETSTATS_H
#define NETSTATS_H

#include <string>
#include <ctime>
#include <stdint.h>

/**
 * Structure that contains information of the stats of a network.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
struct NetStats {
    time_t statsTimestamp;  ///< Timestamp of the stats
    
    uint8_t bssid[6];       ///< Network BSSID
    std::string ssid;       ///< Network SSID
    unsigned short channel; ///< Network channel
    std::string protection; ///< Network protection
    
    double delay;           ///< Network beacon delay (assume that half of the lost packets are packets delayed)
    double loss;            ///< Network beacon loss ratio
    double weightedDelay;   ///< Network beacon delay (assume that the proportion of packets delayed of the lost packets are equal to the proportion of the packets delayed from packets captured)
    int rssi;               ///< Network RSSI
    bool ok;                ///< Reliability of this stats
};

#endif
