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

#ifndef UPDATECHANNELEVENT_H
#define UPDATECHANNELEVENT_H

#include "GUIEvent.h"
#include "GUI.h"
#include "NetStats.h"
#include <list>

/**
 * Event to notify the new computed stats of a channel.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class UpdateChannelEvent : public GUIEvent {
public:

    /**
     * Constructor.
     *
     * @param channel Channel number that will be notified to the GUIs
     * @param stats List with the stats that will be notified to the GUIs
     */
    UpdateChannelEvent(unsigned short channel, const std::list<NetStats>& stats);
    
    /**
     * Notifies to the GUI the updated stats of a channel.
     *
     * @param gui Pointer to the GUI that will execute the event
     */
    void execute(GUI* gui) const;

private:
    unsigned short channel;     ///< Channel number that will be notified to the GUIs
    std::list<NetStats> stats;  ///< List with the stats that will be notified to the GUIs
};

#endif
