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

#ifndef UTILS_H
#define UTILS_H

#include "NetStats.h"
#include <ostream>
#include <string>

namespace Utils {

    /**
     * Write a sequence of bytes in textual format into a std::ostream.
     * The representation follows the format:
     *     aa:7b:..:26
     *
     * @param stream Stream where to write
     * @param bytes Pointer to the sequence of bytes
     * @param size Length of the sequence of bytes
     */
    void writeBytes(std::ostream& stream, const void *bytes, int size);
    
    /**
     * Compares two NetStats to indicate if they are the same network according to their BSSID and SSID.
     *
     * @param n1 NetStats to compare
     * @param n2 NetStats to compare
     * @return n1 and n2 are the same network
     */
    bool sameNetwork(const NetStats& n1, const NetStats& n2);
    
    #ifdef DEBUG
    void writeDebug(const std::string& str);
    #endif
};

#endif
