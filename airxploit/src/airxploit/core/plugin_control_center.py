'''
Created on 05.09.2010

@author: basti
'''

from airxploit.core.blackboard import Blackboard
from airxploit.core.config import Config
from airxploit.core.eventmachine import EventMachine
from airxploit.core.serviceregistry import ServiceRegistry

class PluginControlCenter(object):
    '''
    This module encapsulates the airxploit event machine, service registry, system configuration
    and the blackboard for central information gathering
    '''

    def __init__(self):
        self._blackboard = Blackboard()
        self._cfg = Config()
        self._event = EventMachine()        
        self._service = ServiceRegistry()

    def add_target(self, target):
        """
        add a target
        """
        return self._blackboard.add(target)
    
    def add_info(self, target, section, info):
        """
        add an info to section of target
        """
        return self._blackboard.add_info(target, section, info)
    
    def read_all(self):
        """
        read all information on blackboard
        """
        return self._blackboard.read_all()
     
    def read_all_without_info(self, section):
        """
        get all targets without the given section
        """
        return self._blackboard.read_all_without_info(section)
    
    def register_event(self, name):
        """
        register an event
        """
        return self._event.register(name)
    
    def fire_event(self, name):
        """
        fire an event
        """
        return self._event.fire(name)

    def register_for_event(self, name, obj):
        """
        register a class as listerner to an event
        """
        return self._event.register_for(name, obj)

    def register_service(self, name, plugin):
        """
        register a service (plugin) under given name
        """
        return self._service.register(name, plugin)
    
    def unregister_service(self, name):
        """
        unregister servive with given name
        """
        return self._service.unregister(name)
    
    def get_service(self, name):
        """
        get the service plugin for given service name
        """
        return self._service.get_service(name)

    def get_cfg(self, name):
        """
        get config value for name
        """
        return self._cfg.get(name)
    
    def get_tool(self, name):
        """
        get config tool 
        """
        return self._cfg.cmd(name)
