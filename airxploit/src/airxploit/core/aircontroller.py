'''
Created on 31.07.2010

@author: basti
'''

from time import sleep
from airxploit.scanner.bluetooth import BluetoothScanner
from airxploit.scanner.wlan import WlanScanner
from airxploit.core.target import Wlan, Bluetooth
import airxploit.fuckup
import airxploit.discovery
from airxploit.core.plugincontroller import PluginController
import re

class AirController(object):
    '''
    Control the air!
    Guess what thats the airxploit controller class used by the views
    '''

    BLUETOOTH_EVENT = BluetoothScanner.EVENT
    WLAN_EVENT = WlanScanner.EVENT

    def __init__(self, pcc):
        self._pcc = pcc
        self._plugin_controller = PluginController(pcc)
        self._commands = {
            "discover" : lambda s, p="": s._plugin_controller.load_plugin("discovery", p),
            "exploit" : lambda s, p="": s._plugin_controller.load_plugin("exploit", p),
            "scan" : lambda s,p="": s._plugin_controller.load_plugin("scanner", p),
            "show" : lambda s,p="": s._plugin_controller.show_plugins(p),
            "start" : lambda s,p="": s.scan(p)
                          }
        self._plugin_controller.init_plugins()

    def get_commands(self):
        '''
        get all commands
        '''
        return self._commands.keys()
    
    def run_command(self, cmdline):
        '''
        run a command
        '''
        cmd = re.split(r"\s", cmdline)
        
        if cmd[0] in self._commands:
            if len(cmd) == 2:
                self._commands[cmd[0]](self, cmd[1])
            else:
                self._commands[cmd[0]](self)
        else:
            raise airxploit.fuckup.not_a_command.NotACommand(cmd)

    
    def scan(self, mode=""):
        '''
        scan for targets
        '''        
        if mode == "loop":
            while True:
                self.do_scanning()
                sleep(10)
        else:
            self.do_scanning()
            
    def do_scanning(self):
        scanner = self._plugin_controller.scanner
        if len(scanner) == 0:
            raise airxploit.fuckup.big_shit.BigShit("No scanner loaded")
        
        for plugin in scanner:
            scanner[plugin].run()
    
    def get_wlan_targets(self):
        '''
        get a list of wlan targets
        '''    
        wlan_targets = []
        
        for target in self._pcc.read_all().values():
            if type(target) == Wlan:
                wlan_targets.append(target)
                
        return wlan_targets    

    def get_bluetooth_targets(self):
        '''
        get a list of bluetooth targets
        '''
        bt_targets = []
        
        for target in self._pcc.read_all().values():
            if type(target) == Bluetooth:
                bt_targets.append(target)
                
        return bt_targets    

    def show_plugins(self, category):
        """
        return all plugins of a given category
        """
        return self._plugin_controller.show_plugins(category)
        