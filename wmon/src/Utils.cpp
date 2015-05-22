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

#include "Utils.h"
#include <iomanip>

void Utils::writeBytes(std::ostream& stream, const void *bytes, int size) {
    const unsigned char * pbytes = static_cast<const unsigned char*> (bytes);
    stream << std::hex << std::setfill('0');
    for (int i = 0; i < size; ++i) {
        if (i != 0) stream << ":";
        stream << std::setw(2) << static_cast<unsigned int> (pbytes[i]);
    }
    stream << std::dec;
}

bool Utils::sameNetwork(const NetStats& n1, const NetStats& n2) {
    bool cmp = true;
    for (int i = 0; cmp and i < 6; ++i) cmp = n1.bssid[i] == n2.bssid[i];
    return cmp and n1.ssid == n2.ssid;
}

#ifdef DEBUG
#include <fstream>

void Utils::writeDebug(const std::string& str) {
    static std::ofstream file("DEBUG.txt", std::ios_base::out | std::ios_base::app);
    file << str << std::endl;
}
#endif

