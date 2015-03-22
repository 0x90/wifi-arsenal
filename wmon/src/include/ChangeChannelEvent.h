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

#ifndef CHANGECHANNELEVENT_H
#define CHANGECHANNELEVENT_H

#include "GUIEvent.h"
#include "GUI.h"

/**
 * Event to notify a change of channel. 
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class ChangeChannelEvent : public GUIEvent {
public:

    /**
     * Constructor.
     *
     * @param channel Channel number that will be notified to the GUIs
     */
    ChangeChannelEvent(unsigned short channel);
    
    /**
     * Notifies to the GUI a change of channel.
     *
     * @param gui Pointer to the GUI that will be notified
     */
    void execute(GUI* gui) const;
    
private:
    unsigned short channel; ///< Channel number that will be notified to the GUIs
};

#endif
