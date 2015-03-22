'''
Created on 25.07.2010

@author: basti
'''

import errno
import sys
from pythonwifi.iwlibs import Wireless
import airxploit.core
import logging
from airxploit.fuckup.permission_denied import PermissionDenied
from airxploit.fuckup.big_shit import BigShit

class WlanScanner(object):
    '''
    Scan for Wlan devices
    You can register for WLAN_TARGET_FOUND event to get notified if we found somethin
    '''

    EVENT = "WLAN_TARGET_FOUND"

    frequency_channel_map = { 
                                "2.412GHz" : 1,
                                "2.417GHz" : 2,
                                 "2.422GHz" : 3,
                                 "2.427GHz" : 4,
                                 "2.432GHz" : 5,
                                 "2.437GHz" : 6,
                                 "2.442GHz" : 7,
                                 "2.447GHz" : 8,
                                 "2.452GHz" : 9,
                                 "2.457GHz" : 10,
                                 "2.462GHz" : 11,
                                 "2.467GHz" : 12,
                                 "2.472GHz" : 13,
                                 "2.484GHz" : 14,
                                 "5.180GHz" : 36,
                                 "5.200GHz" : 40,
                                 "5.220GHZ" : 44,
                                 "5.240GHz" : 48,
                                 "5.260GHz" : 52,
                                 "5.280GHz" : 56,
                                 "5.300GHz" : 60,
                                 "5.320GHz" : 64,
                                 "5.500GHz" : 100,
                                 "5.520GHz" : 104,                                
                                 "5.540GHz" : 108,                                
                                 "5.560GHz" : 112,                                
                                 "5.580GHz" : 116,                                
                                 "5.600GHz" : 120,                                
                                 "5.620GHz" : 124,                                
                                 "5.640GHz" : 128,                                
                                 "5.660GHz" : 132,                                
                                 "5.680GHz" : 136,                                
                                 "5.700GHz" : 140,                                
                                 "5.735GHz" : 147,                                
                                 "5.755GHz" : 151,                                
                                 "5.775GHz" : 155,                                
                                 "5.795GHz" : 159,                                
                                 "5.815GHz" : 163,                                
                                 "5.835GHz" : 167,                                
                                 "5.785GHz" : 171                                
                                 }

    def __init__(self, pcc):
        if pcc.get_cfg("wlan_device") == None:
            raise airxploit.fuckup.plugin_init.PluginInit("wlan_device config undefined")
        
        self.result = set()
        self._pcc = pcc
        self._pcc.register_event(WlanScanner.EVENT)
        self._pcc.register_service("WlanScanner", self)
    
    def run(self):
        """
        run the plugin
        """
        current_targets = set()
        logging.debug(str(self.__class__) + " Scanning for wlan devices")
        
        try:
            wifi = Wireless( self._pcc.get_cfg("wlan_device") )
            results = wifi.scan()
        except IOError:
            raise PermissionDenied("Cannot scan for wifi :(")
            sys.exit(1)
        
        if len(results) > 0:
            for ap in results:
#               print ap.bssid + " " + frequencies.index(wifi._formatFrequency(ap.frequency.getFrequency())) + " " + ap.essid + " " + ap.quality.getSignallevel()
                target = airxploit.core.target.Wlan()
                target.quality = ap.quality.getSignallevel()
                target.name = ap.essid
                target.addr = ap.bssid
                target.channel = WlanScanner.frequency_channel_map.get( ap.frequency.getFrequency() )
                current_targets.add(target)
                logging.debug(str(self.__class__) + " Found wlan device " + ap.bssid + " " + " " + ap.essid)

        if self.result == current_targets:
            got_new_targets = False
        else:
            got_new_targets = True

        if got_new_targets:
            for target in current_targets:
                if target not in self.result:
                    self._pcc.add_target( target )

            self.result = current_targets
            self._pcc.fire_event(WlanScanner.EVENT)    
