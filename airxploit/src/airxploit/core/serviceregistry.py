'''
Created on 04.09.2010

@author: basti
'''

import logging
import airxploit.fuckup

class ServiceRegistry(object):
    '''
    Register a plugin as a service
    Let other plugins load that services
    '''
    
    def __init__(self):
        self._services = {}
        
    def register(self, name, plugin):
        """
        register a plugin under the given name
        """
        if name not in self._services:
            self._services[name] = plugin
            logging.debug(str(self.__class__) + " Registered service " + name + " -> " + str(type(plugin)))
        else:
            logging.error(str(self.__class__) + " Service " + name + " already registered")

    def unregister(self, name):
        """
        unregister service with given name
        """
        if name in self._services:
            del self._services[name]
            logging.debug(str(self.__class__) + " Unregister service " + name)
        else:
            raise airxploit.fuckup.not_a_service.NotAService(name)
        
    def get_service(self, name):
        """
        get plugin with service name
        """
        if name in self._services:
            return self._services[name]
        else:
            raise airxploit.fuckup.not_a_service.NotAService(name)
    
    def services(self):
        """
        get a list of service names
        """
        return self._services.keys()
