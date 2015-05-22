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

#ifndef GUIEVENTDISPATCHER_H
#define GUIEVENTDISPATCHER_H

#include "GUI.h"
#include "GUIEvent.h"
#include <list>
#include <queue>
#include <pthread.h>

/**
 * Mecanism to inform GUIs of events.
 *
 * @author David Garcia Villalba    <dagavi@gmail.com>
 * @author Daniel López Rovira      <daniellopezrovira@gmail.com>
 * @author Marc Portoles Comeras    <mportoles@cttc.cat>
 * @author Albert Cabellos Aparicio <acabello@ac.upc.edu>
 */
class GUIEventDispatcher {
public:

    /**
     * Run the event dispatcher thread.
     */
    static void run();
    
    /**
     * Stop the event dispatcher thread.
     */
    static void stop();
    
    /**
     * Register a GUIEvent to be notified to the registered GUI, signaling the eventMutex conditional variable.
     * After his execution, the event is deleted with a call "delete event;".
     *
     * @param event Event to be notified.
     */
    static void registerEvent(const GUIEvent* event);
    
    /**
     * Register a GUI.
     *
     * @param gui GUI that will be registered
     */
    static void registerGUI(GUI* gui);
    
    /**
     * Unregister a GUI.
     *
     * @param gui GUI that will be unregistered
     */
    static void unregisterGUI(GUI* gui);

private:
    static bool end; ///< Indicates that the event dispatcher thread has to end her execution
    
    static std::queue<const GUIEvent*> events;  ///< Registered events
    static pthread_t eventDispatcherThread;     ///< Structure of the event dispatcher thread
    static pthread_mutex_t eventMutex;          ///< Mutex for the events attribute
    static pthread_cond_t eventCondVar; ///< Conditional variable for the events attribute. Signaled when events or end attributes are modified
    
    static std::list<GUI*> guis;        ///< Registered GUIs
    static pthread_mutex_t guisMutex;   ///< Mutex for the guis attribute
    
    /**
     * Function that calls GUIEvent::execute() of all the GUIEvent of the events attribute
     * for all the GUI of the guis attribute while the end attribute is true.
     *
     * @param param Argument to math with the pthread function. Not used.
     */
    static void* eventDispatcher(void* param);
};

#endif
