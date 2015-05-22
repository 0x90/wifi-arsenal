'''
Created on 07.08.2010

@author: basti
'''
import lightblue
import logging
from airxploit.scanner.bluetooth import BluetoothScanner

class SdpDiscovery(object):
    '''
    Browse SDP services of a Bluetooth target
    '''

    EVENT = "BLUETOOTH_SDP_FOUND"
    SECTION = "sdp"
    
    def __init__(self, pcc):
        self._pcc = pcc
        self._pcc.register_event(SdpDiscovery.EVENT)
        self._pcc.register_for_event(BluetoothScanner.EVENT, self)
        self._pcc.register_service("SdpDiscovery", self)
        self.result = []
        
    def run(self):
        """
        run the plugin
        """
        logging.debug(str(self.__class__) + " run()")
        
        for target in self._pcc.read_all_without_info(SdpDiscovery.SECTION):
            try:
                logging.debug(str(self.__class__) +  " Executing SDP browse for target " + target.addr)
                services = []
                
                for sdp in lightblue.findservices(target.addr):
                    service = SdpService()
                    service.name = sdp[2]
                    service.channel = sdp[1]
                    services.append(service)
                
                if services.count > 0:    
                    self.result = services
                    self._pcc.add_info(target, SdpDiscovery.SECTION, services)
                    self._pcc.fire_event(SdpDiscovery.EVENT)

            except IOError:
                pass
        
    
    def got_event(self, event):
        """
        event callback function
        """
        logging.debug(str(self.__class__) + " Got event " + event)        
        self.run()
        
class SdpService(object):
    """
    encapsulate a sdp service
    """
    def __init__(self):
        self.name = ""
        self.channel = None
        
    def __str__(self):
        return str(self.channel) + " " + self.name
