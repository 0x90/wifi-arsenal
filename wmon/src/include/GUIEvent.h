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

#ifndef GUIEVENT_H
#define GUIEVENT_H

#include "GUI.h"

/**
 * Executable GUI event.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class GUIEvent {
public:
    
    /**
     * Destructor
     */
    virtual ~GUIEvent();

    /**
     * Pure virtual method that execute the event logic.
     *
     * @param gui Pointer to the GUI that will execute the event
     */
    virtual void execute(GUI* gui) const = 0;
};

#endif
