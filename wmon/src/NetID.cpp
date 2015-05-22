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

#include "NetID.h"
#include "Utils.h"
#include <cstring>

NetID::NetID(const uint8_t bssid[6], const char ssid[]) {
    setBSSID(bssid);
    setSSID(ssid);
}

void NetID::setBSSID(const uint8_t bssid[6]) {
    memcpy(this->bssid, bssid, sizeof(this->bssid));
}

const uint8_t* NetID::getBSSID() const {
    return bssid;
}

void NetID::setSSID(const char ssid[]) {
    this->ssid = std::string(ssid);
}

std::string NetID::getSSID() const {
    return ssid;
}

bool NetID::operator < (const NetID &n) const {
    for (int i = 0; i < sizeof(bssid); ++i) {
        if (bssid[i] < n.bssid[i]) return true;
        if (bssid[i] > n.bssid[i]) return false;
    }
    return ssid < n.ssid;
}

bool NetID::operator == (const NetID &n) const {
    for (int i = 0; i < sizeof(bssid); ++i) {
        if (bssid[i] != n.bssid[i]) return false;
    }
    return ssid == n.ssid;
}

const NetID& NetID::operator = (const NetID &n) {
    if (this != &n) {
        memcpy(bssid, n.bssid, sizeof(bssid));
        ssid = n.ssid;
    }
    
    return *this;
}

