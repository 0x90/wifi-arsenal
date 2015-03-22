'''
Created on 31.07.2010

@author: basti
'''
import logging
import airxploit.fuckup

class EventMachine(object):
    '''
    The airXploit eventmachine
    Scanner, tools, exploits and other plugin can register and fire events
    while other plugins register themself as listeners
    think of observer pattern ;)
    '''

    def __init__(self):
        self._events = {}
        self._events["ALL"] = 1
        
        self._event_listeners = {}
        self._event_listeners["ALL"] = {}
        
    def register(self, name):
        '''
        register an event
        '''
        if name != "ALL":
            self._events[name] = 1
            self._event_listeners[name] = {}
    
    def unregister(self, name):
        '''
        unregister an event
        '''
        if name in self._events and name != "ALL":
            del self._events[name]
            del self._event_listeners[name]
        else:
            logging.error(str(self.__class__) + " Unknown event " + name)
            raise airxploit.fuckup.not_an_event.NotAnEvent(name)
        
    def register_for(self, name, obj):
        '''
        register yourself as a listener for the given event
        listeners must implement an gotEvent(name) method
        event name "ALL" will register for all events
        '''
        if name in self._events or name == "ALL":
            logging.debug(str(self.__class__) + " Registering " + str(type(obj)) + " for event " + name)            
            self._event_listeners[name][obj] = 1
        else:
            logging.error(str(self.__class__) + " Unknown event " + name)
            raise airxploit.fuckup.not_an_event.NotAnEvent(name)
    
    def unregister_for(self, name, obj):
        '''
        unregister as listener for event
        '''
        if name in self._events or name == "ALL":
            logging.debug(str(self.__class__) + " Unregistering " + str(type(obj)) + " from event " + name)
            del self._event_listeners[name][obj]
        else:
            logging.error(str(self.__class__) + " Unknown event " + name)
            raise airxploit.fuckup.not_an_event.NotAnEvent(name)
        
    def fire(self, name):
        '''
        fire an event!
        this will iterate over all event listeners and call their gotEvent() method
        '''
        if name in self._events:
            logging.debug(str(self.__class__) + " Fireing event " + name)
            notify_listeners = {}
            notify_listeners = self._event_listeners[name]
            notify_listeners.update(self._event_listeners["ALL"])
            
            del_listeners = []
            
            for listener in notify_listeners:
                try:
                    listener.got_event(name)
                except AttributeError:
                    del_listeners.append(listener)
            
            for listener in del_listeners:
                del self._event_listeners[name][listener]

    def events(self):
        '''
        get a list of registered events
        '''
        return self._events.keys()
