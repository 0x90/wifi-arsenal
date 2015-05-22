'''
Created on 08.08.2010

@author: basti
'''
from airxploit.scanner.bluetooth import BluetoothScanner
import logging
import lightblue

class RfcommDiscovery(object):
    '''
    A simple RFCOMM scanner thats tries to connect to all 20 channels
    '''

    EVENT = "BLUETOOTH_RFCOMM_FOUND"
    SECTION = "rfcomm"

    def __init__(self, pcc):
        self._pcc = pcc
        self._pcc.register_event(RfcommDiscovery.EVENT)
        self._pcc.register_for_event(BluetoothScanner.EVENT, self)
        self._pcc.register_service("RfcommDiscovery", self)
        self.result = []

    def run(self):
        """
        run the plugin
        """
        logging.debug(str(self.__class__) + " run()")
        
        for target in self._pcc.read_all_without_info(RfcommDiscovery.SECTION):
            logging.debug(str(self.__class__) + " Executing RFCOMM scanner for target " + target.addr)
            self.result = []
            channels = []
            
            for scan in range(20):
                channel = RfcommService()
                channel.nr = scan+1

                try:
                    sock = lightblue.socket()
                    sock.connect((target.addr, scan+1))
                    sock.close
                
                    channel.open = True
                    logging.debug(str(self.__class__) + " Channel " + str(scan+1) + " open")
                except IOError:
                    channel.open = False
                    logging.debug(str(self.__class__) + " Channel " + str(scan+1) + " closed")
                
                channels.append(channel)
                
            if channels.count > 0:    
                self.result = channels
                self._pcc.add_info(target, RfcommDiscovery.SECTION, channels)
                self._pcc.fire_event(RfcommDiscovery.EVENT)
            
    def got_event(self, event):
        """
        event callback function
        """        
        logging.debug(str(self.__class__) + " Got event " + event)
        self.run()


class RfcommService(object):
    """
    Encapsulate a rfcomm service
    """    
    def __init__(self):
        self.nr = 0
        self.open = False
        
    def __str__(self):
        return "RFCOMM channel " + str(self.nr) + " " + str(self.open)
    