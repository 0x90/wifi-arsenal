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

/*
This class contain the airmon-ng script code from the aircrack-ng suite.

aircrack-ng Author:     Thomas d'Otreppe <tdotreppe@aircrack-ng.org> [from AUTHORS file]
aircrack-ng webpage:    www.aircrack-ng.org
License:                GNU General Public License, version 2 (http://www.gnu.org/licenses/gpl-2.0.html)
*/

#ifndef AIRMONNG_H
#define AIRMONNG_H

#include <string>

/**
 * Class that contains the Airmon-NG script and provides static methods
 * to create and removes virtual monitor interfaces.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class AirmonNG {
public:

    /**
     * Creates a virtual monitor interface from another interface.
     *
     * @param interface The interface identifier to use for create the monitor interface
     * @return The new monitor interface identifier. An empty string if error
     */
    static std::string createMonitorInterface(const std::string& interface);
    
    /**
     * Deletes a virtual monitor interface.
     *
     * @param interface The interface identifier
     */
    static void deleteMonitorInterface(const std::string& interface);

private:
    static const char* script; ///< Airmon-Script
    static const unsigned int CREATEMONITORCMDBUFFER = 32; ///< Size of the buffer where put the monitor's interface name
};

#endif

