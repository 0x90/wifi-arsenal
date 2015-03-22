'''
Created on 25.07.2010

@author: basti
'''

import lightblue
import airxploit.core
import logging

class BluetoothScanner(object):
    '''
    Scan for Bluetooth devices
    You can register for BLUETOOTH_TARGET_FOUND event to get notified if we found somethin
    '''

    EVENT = "BLUETOOTH_TARGET_FOUND"

    def __init__(self, pcc):
        self.result = set()
        self._pcc = pcc
        self._pcc.register_event(BluetoothScanner.EVENT)
        self._pcc.register_service("BluetoothScanner", self)
        
    def run(self):
        """
        run the plugin
        """
        current_targets = set()
        logging.debug(str(self.__class__) + " Scanning for bluetooth devices")
        
        try:
            for device in lightblue.finddevices():
                target = airxploit.core.target.Bluetooth()
                target.addr = device[0]
                target.name = device[1]
                current_targets.add(target)
                logging.debug(str(self.__class__) + " Found bluetooth device " + device[0] + " " + device[1])

        except IOError:
            pass
        
        if self.result == current_targets:
            got_new_targets = False
        else:
            got_new_targets = True
            
        if got_new_targets:
            for target in current_targets:
                if target not in self.result:
                    self._pcc.add_target( target )

            self.result = current_targets
            self._pcc.fire_event(BluetoothScanner.EVENT)    
