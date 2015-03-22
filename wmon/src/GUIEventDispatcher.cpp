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

#include "GUIEventDispatcher.h"

bool GUIEventDispatcher::end = false;

pthread_t GUIEventDispatcher::eventDispatcherThread;

std::queue<const GUIEvent*> GUIEventDispatcher::events;
pthread_mutex_t GUIEventDispatcher::eventMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t GUIEventDispatcher::eventCondVar = PTHREAD_COND_INITIALIZER;

std::list<GUI*> GUIEventDispatcher::guis;
pthread_mutex_t GUIEventDispatcher::guisMutex = PTHREAD_MUTEX_INITIALIZER;

void GUIEventDispatcher::run() {
    end = false;
    pthread_create(&eventDispatcherThread, NULL, eventDispatcher, NULL);
}

void GUIEventDispatcher::stop() {
    pthread_mutex_lock(&eventMutex);
    end = true;
    pthread_cond_signal(&eventCondVar);
    pthread_mutex_unlock(&eventMutex);
    pthread_join(eventDispatcherThread, NULL);
    while (not events.empty()) {
        delete events.front();
        events.pop();
    }
}

void GUIEventDispatcher::registerEvent(const GUIEvent* event) {
    pthread_mutex_lock(&eventMutex);
    if (not end) {
        events.push(event);
        pthread_cond_signal(&eventCondVar);
    }
    else delete event;
    pthread_mutex_unlock(&eventMutex);
}

void GUIEventDispatcher::registerGUI(GUI* gui) {
    pthread_mutex_lock(&guisMutex);
    guis.push_back(gui);
    pthread_mutex_unlock(&guisMutex);
}

void GUIEventDispatcher::unregisterGUI(GUI* gui) {
    pthread_mutex_lock(&guisMutex);
    guis.remove(gui);
    pthread_mutex_unlock(&guisMutex);
}

void* GUIEventDispatcher::eventDispatcher(void* param) {
    while (not end) {
        // wait event or end
        pthread_mutex_lock(&eventMutex);
        while (events.empty() and not end) pthread_cond_wait(&eventCondVar, &eventMutex);
        
        const GUIEvent* event = NULL;
        if (not end) {
            event = events.front();
            events.pop();
        }
        pthread_mutex_unlock(&eventMutex);
        
        if (event != NULL) {
            // do Event
            pthread_mutex_lock(&guisMutex);
            for (std::list<GUI*>::const_iterator observer = guis.begin(); observer != guis.end(); ++observer) {
                event->execute(*observer);
            }
            pthread_mutex_unlock(&guisMutex);
            delete event;
        }
    }
    pthread_exit(NULL);
}

