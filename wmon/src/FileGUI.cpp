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

#include "FileGUI.h"
#include "Utils.h"

FileGUI::FileGUI(const char path[]) {
    file.open(path, std::ios_base::out | std::ios_base::app);
    file.setf(std::ios::fixed);
    file.precision(2);
    maxTimestamp = 0;
}

FileGUI::~FileGUI() {
    file.close();
}

void FileGUI::updateChannel(unsigned short channel, const std::list<NetStats>& stats) {
    time_t oldMaxTimestamp = maxTimestamp;
    
    for (std::list<NetStats>::const_iterator ns = stats.begin(); ns != stats.end(); ++ns) {
        if (ns->statsTimestamp >= oldMaxTimestamp) {
            if (ns->statsTimestamp > maxTimestamp) maxTimestamp = ns->statsTimestamp;
            struct tm* timeInfo = localtime(&ns->statsTimestamp);
            char iso8601Time[25];
            strftime(iso8601Time, sizeof(iso8601Time), "%FT%H:%M:%S%z", timeInfo);
            
            file << ns->statsTimestamp << ',' << iso8601Time << ',';
            
            Utils::writeBytes(file, ns->bssid, 6);
            
            file << ',' <<
            ns->channel << ',' <<
            ns->weightedDelay << ',' <<
            ns-> loss << ',' <<
            ns->rssi << ',' <<
            (ns->ok ? 'y':'n') << ',' <<
            ns->ssid << std::endl;
        }
    }
}

bool FileGUI::fileOK() const {
    return not file.fail();
}

