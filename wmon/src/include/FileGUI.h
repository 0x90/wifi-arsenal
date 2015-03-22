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

#ifndef FILEGUI_H
#define FILEGUI_H

#include "GUI.h"
#include <fstream>
#include <ctime>

/**
 * Writes the results to a file.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class FileGUI : public GUI {
public:

    /**
     * Creates the GUI object to write in the indicated path.
     *
     * @param path Path of the file to write
     */
    FileGUI(const char path[]);
    
    /**
     * Destructor.
     */
    ~FileGUI();
    
    /**
     * Notifies the updated stats of the networks of a channel.
     *
     * @param channel Channel of the update notification
     * @param stats NetStats with the updated information
     */
    void updateChannel(unsigned short channel, const std::list<NetStats>& stats);
    
    /**
     * Checks if the stream is correctly created.
     *
     * @return Stream is correctly created
     */
    bool fileOK() const;

private:
    std::ofstream file;  ///< File stream structure
    time_t maxTimestamp; ///< Maximum timestamp detected
};

#endif
