#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import time
import re
import commands
import glob
import sqlite3
import binascii

from threading import Thread
from PyQt4 import QtGui, QtCore
from airmode_gui import Ui_Main_window
#from PyQt4.QtGui import QApplication
from PyQt4.QtGui import QMainWindow
from airmode_config import *

#
# Hex key to ascii
#
def key_to_ascii(key):
    ascii_string = ''

    splitted = key.split(':')

    for i in splitted:
        if re.match("^[0-9A-Fa-f]{2}$", i):
            ascii_string = ascii_string + binascii.a2b_hex(i)

    return ascii_string

#
# Thread for the asyncronous execution
# of commands
#
class Command_thread(Thread):
    def __init__ (self, command, use_term = True, callback = None):
        Thread.__init__(self)
        self.command = command
        self.use_term = use_term
        self.callback = callback

    def run(self):

        # exec command
        print (self.command)

        # use terminal emulator?
        if self.use_term:
            commands.getstatusoutput(def_term + " -e 'bash -c \"" + self.command + "; read; \"'")
        
        else:
            commands.getstatusoutput(self.command)
            
        # callback
        if hasattr(self.callback, '__call__'):
           self.callback()

#
# Retarded Kill
#
class RetardedKill(Thread):
    def __init__ (self, prog, sec):
        Thread.__init__(self)
        self.prog = prog
        self.sec  = sec

    def run(self):
        time.sleep(self.sec)
        commands.getstatusoutput("killall " + self.prog)

#
# For the callbacks function
# extend Main_window class (that contains the GUI)
#
class Main_window_ex(QMainWindow, Ui_Main_window):
    # Print the output in the GUI with a timestamp and with exit_code
    # this function should be used instead of other form of output printing
    #
    def __init__(self, parent = None):
        """
        Default Constructor. It can receive a top window as parent. 
        """
        QMainWindow.__init__(self, parent)
        self.setupUi(self)
                   
    def output(self, out_text, exit_code):
        # print the output in the text_output widget (QTextEdit)
        # success
        if exit_code==0:
            self.text_output.append( '<b>' + time.strftime("%H:%M:%S", time.localtime()) + '</b> - ' + out_text + ' [<font color="#00aa00">Success</font>]')
        # failure
        else:
            self.text_output.append( '<b>' + time.strftime("%H:%M:%S", time.localtime()) + '</b> - ' + out_text + ' [<font color="#ff0000">Failure</font>]')

    #
    # Print the output in the GUI with a timestamp but without exit_code
    # this function should be used instead of other form of output printing
    #
    def direct_output(self, out_text):
        # print the output in the text_output widget (QTextEdit)
        self.text_output.append( '<b>' + time.strftime("%H:%M:%S", time.localtime()) + '</b> - ' + out_text)

    #
    # Check if the requested options are consistent
    #
    def check_options(self, options):

        if self.periferica_opt & options > 0:
            if self.periferica == "":
                self.output("no interface selected", 1)
                return 0

        if self.mymon_opt & options > 0:
            if self.mymon == "":
                self.output("monitor interface is not set", 1)
                return 0

        if self.mymac_opt & options > 0:
            if self.mymac == "" or not re.match("^[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}$", self.mymac):
                self.output("interface mac is not set (or wrong)", 1)
                return 0

        if self.ac_opt & options > 0:
            if self.ac == "" or not re.match("^[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}$", self.ac):
                self.output("no network selected", 1)
                return 0

        if self.canale_opt & options > 0:
            if self.canale == "" or self.canale < 0:
                self.output("no channel selected", 1)
                return 0

        if self.essid_opt & options > 0:
            if self.essid == "":
                self.output("no network selected", 1)
                return 0

        if self.mval_opt & options > 0:
            if self.mval == "" or self.mval < 1:
                self.output("wrong arp request number", 1)
                return 0

        if self.nval_opt & options > 0:
            if self.nval == "" or self.nval < 1:
                self.output("wrong arp request number", 1)
                return 0

        if self.ac_victim_opt & options > 0:
            if self.ac_victim == "" or not re.match("^[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}$", self.ac_victim):
                self.output("wrong victim mac", 1)
                return 0

        if self.ac_victim_wpa_opt & options > 0:
            if self.ac_victim_wpa == "" or not re.match("^[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}$", self.ac_victim_wpa):
                self.output("wrong victim mac", 1)
                return 0

        if self.deauth_WPA_num_opt & options > 0:
            if self.deauth_WPA_num == "" or self.deauth_WPA_num < 1:
                self.output("wrong deauth number", 1)
                return 0

        if self.dfile_opt & options > 0:
            if self.dfile == "":
                self.output("dictionary is not set", 1)
                return 0

        if self.dfile2_opt & options > 0:
            if self.dfile2 == "":
                self.output("dictionary is not set", 1)
                return 0

        if self.change_mac_int_opt & options > 0:
            if self.change_mac_int == "":
                self.output("interface name is not set", 1)
                return 0

        if self.change_mac_mac_opt & options > 0:
            if self.change_mac_mac == "" or not re.match("^[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}$", self.change_mac_mac):
                self.output("wrong mac address", 1)
                return 0

        if self.rtablesfile1_opt & options > 0:
            if self.rtablesfile1 == "":
                self.output("rainbow tables files is not set", 1)
                return 0

        if self.intf_mode_opt & options > 0:
            if self.intf_mode != 'Monitor':
                self.output("interface not in monitor mode", 1)
                return 0

        return 1

    #
    # Capture replay packets (ARP request)
    #
    def slot_wep_capture_req(self):
        if self.check_options(self.ac_opt | self.mval_opt | self.nval_opt | self.mymon_opt | self.mymac_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -2 -p 0841 -b ' + self.ac + ' -c FF:FF:FF:FF:FF:FF -f 1 -m ' + self.mval + ' -n ' + self.nval + ' -h ' + self.mymac + ' ' + self.mymon
            #command = 'aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF -b ' + self.ac + ' -h ' + self.mymac + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('ARP request attack: Capture replay packets with ' + self.mymon)


    #
    # Crack WPA password dictionary
    #
    def slot_crack_wpa_aircrack(self):
        if self.check_options(self.ac_opt | self.dfile_opt) == 0:
            pass
        else:
            command = 'aircrack-ng -w ' + self.dfile + ' -b ' + self.ac + ' ' + config_dir + '*.cap | tee ' + config_dir + 'aircrack-log.txt'
            ct = Command_thread(command, True, self.add_key_to_database)
            ct.start()

            self.direct_output("Cracking WPA password with dictionary launched (remember to save database's changes)")


    #
    # Crack WPA password pyrit
    #
    def slot_crack_wpa_pyrit(self):
        if self.check_options(self.essid_opt | self.dfile2_opt) == 0:
            pass
        else:
            command = 'pyrit -e "' + self.essid + '" -i "' + self.dfile2 + '" -r "' + config_dir + '*.cap" attack_passthrough'
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Cracking WPA password with pyrit launched')

    #
    # Restore original MAC Address
    #
    def slot_mac_restore(self):
        if self.check_options(self.change_mac_int_opt) == 0:
            pass
        else:
            command = 'ifconfig ' + self.change_mac_int + ' down hw ether `cat ' + config_dir + '.macaddress-backup`; ifconfig ' + self.change_mac_int + ' up'
            ct = Command_thread(command, False)
            ct.start()

            self.direct_output('Restored original MAC address on interface ' + self.change_mac_int)

    #
    # Put the card in monitor mode
    #
    def slot_monitor(self):
        
        if self.check_options(self.periferica_opt) == 0:
            pass
        
        elif self.intf_mode == "Monitor":
            status = commands.getstatusoutput('airmon-ng stop '  + self.periferica)
            if status[0] != 0:
                self.output(status[1], status[0])
            else:
                self.output("Monitor off: " + self.periferica, status[0])
        else:
            status = commands.getstatusoutput('airmon-ng stop '  + self.periferica + '; airmon-ng start ' + self.periferica)
            if status[0] != 0:
                self.output(status[1], status[0])
            else:
                self.output("Monitor on: " + self.periferica, status[0])
        self.slot_reload_interfaces()

    #
    # Start Client Fragmentation Attack
    #
    def slot_wep_arp_inj_cfrag(self):
        if self.check_options(self.mymon_opt | self.intf_mode_opt | self.ac_victim_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -7 -c ' + self.ac_victim + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Client Fragmentation attack started, using ' + self.mymon)

    #
    # Forged packet injection on the victim access point (ChopChop)
    #
    def slot_wep_arp_inj_chop(self):
        if self.check_options(self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -2 -r ' + config_dir + 'output_FORGED ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('ChopChop attack: Inject arp packet with ' + self.mymon)

    #
    # Forged packet injection on the victim access point (Fragmentation)
    #
    def slot_wep_arp_inj_frag(self):
        if self.check_options(self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -2 -r ' + config_dir + 'output_FORGED2 ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Fragmentation attack: Inject arp packet with ' + self.mymon)

    #
    # Associate with AP, use fake auth
    #
    def slot_fake_auth(self):
        if self.check_options(self.essid_opt | self.ac_opt | self.mymon_opt | self.mymac_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -1 0 -e "' + self.essid + '" -a ' + self.ac + ' -h ' + self.mymac + ' ' + self.mymon
            ct = Command_thread(command, False)
            ct.start()

            self.direct_output('Fake authentication with ' + self.mymon)

    #
    # Create the ARP packet to be injected on the victim access point (ChopChop)
    #
    def slot_wep_create_arp_chop(self):
        if self.check_options(self.ac_opt | self.mymac_opt) == 0:
            pass
        else:
            command = 'packetforge-ng -0 -a ' + self.ac + ' -h ' + self.mymac + ' -k 255.255.255.255 -l 255.255.255.255 -y ' + config_dir + '*.xor -w ' + config_dir + 'output_FORGED '
            ct = Command_thread(command, False)
            ct.start()

            self.direct_output('ChopChop attack: ARP packet created')

    #
    # Create the ARP packet to be injected on the victim self.access point (Fragmentation)
    #
    def slot_wep_create_arp_frag(self):
        if self.check_options(self.ac_opt | self.mymac_opt) == 0:
            pass
        else:
            command = 'packetforge-ng -0 -a ' + self.ac + ' -h ' + self.mymac + ' -k 255.255.255.255 -l 255.255.255.255 -y ' + config_dir + '*.xor -w ' + config_dir + 'output_FORGED2'
            ct = Command_thread(command, False)
            ct.start()

            self.direct_output('Fragmentation attack: ARP packet created')

    #
    # Start ChopChop attack
    #
    def slot_wep_start_chop(self):
        if self.check_options(self.mymon_opt | self.mymac_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -4 -h ' + self.mymac + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('ChopChop attack started, using ' + self.mymon)

    #
    # Start Fragmentation Attack
    #
    def slot_wep_start_frag(self):
        if self.check_options(self.ac_opt | self.mymon_opt | self.mymac_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -5 -b ' + self.ac + ' -h ' + self.mymac + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Fragmentation attack started, using ' + self.mymon)

    #
    # Start ARP replay Attack
    #
    def slot_wep_start_rep(self):
        if self.check_options(self.ac_opt | self.mymon_opt | self.mymac_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -3 -b ' + self.ac + ' -h ' + self.mymac + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('ARP replay attack started, using ' + self.mymon)

    #
    # Start sniffing and logging
    #
    def slot_start_sniffing(self):
        dump_file = config_dir + 'sniff_dump'

        if self.check_options(self.canale_opt | self.ac_opt | self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'airodump-ng -c ' + self.canale + ' -w ' + dump_file  + ' --bssid ' + self.ac + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Sniffing and logging started with ' + self.mymon)

    #
    # Performs a test of injection
    #
    def slot_test_inj(self):
        if self.check_options(self.ac_opt | self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -9 -a ' + self.ac + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('WEP: Injection test with ' + self.mymon)

    #
    # Client deauthentication (WPA handshake)
    #
    def slot_wpa_deauth_hand(self):
        if self.check_options(self.ac_opt | self.deauth_WPA_num_opt | self.ac_victim_wpa_opt | self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'aireplay-ng -0 ' + self.deauth_WPA_num + ' -a ' + self.ac + ' -c ' + self.ac_victim_wpa + ' ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('WPA handshake attack: Client deauthentication with ' + self.mymon)

    #
    # WPS Test
    #
    def slot_start_wps_test(self):
        if self.check_options(self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'wash -i ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('start WPS test...')



    #
    # WPA PIN attack (WPS attack)
    #
    def slot_start_wps_attack(self):
        if self.check_options(self.ac_opt | self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'reaver -i ' + self.mymon + ' -b ' + self.ac + '-a-w' 
            ct = Command_thread(command)
            ct.start()

            self.direct_output('WPA WPS attack: ' + self.ac)

    #
    # Clean all the old session files
    #
    def slot_gath_clean(self):
        commands.getstatusoutput('rm -f ' + config_dir + '*.cap ' + config_dir + '*.csv ' + config_dir + '*.xor ' + config_dir + '*.netxml ')
        self.direct_output('Logs cleaned')

    #
    # WPA Rainbow Tables Cracking
    #
    def slot_crack_wpa_rainbow_tables(self):
        if self.check_options(self.essid_opt | self.rtablesfile1_opt) == 0:
            pass
        else:
            command = 'cowpatty -r ' + config_dir + '*.cap -d ' + self.rtablesfile1 + ' -s "' + self.essid + '"'
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Cracking WPA with rainbow tables launched')

    #
    # Aircrack decript WEP password
    #
    def slot_crack_wep_aircrack(self):
        if self.check_options(self.ac_opt) == 0:
            pass
        else:
            command = 'aircrack-ng -z -b ' + self.ac + ' ' + config_dir + '*.cap | tee ' + config_dir + 'aircrack-log.txt'
            ct = Command_thread(command, True, self.add_key_to_database)
            ct.start()

            self.direct_output("Cracking WEP with aircrack launched (remember to save database's changes)")

    #
    # Start Hirte attack ad-hoc mode
    #
    def slot_wep_start_hirte_adhoc(self):
        if self.check_options(self.essid_opt | self.canale_opt | self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'airbase-ng -c ' + self.canale + ' -e "' + self.essid + '" -N -A -W 1 ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Hirte attack ad-hoc mode started with ' + self.mymon)

    #
    # Start Hirte attack self.access point mode
    #
    def slot_wep_start_hirte_ap(self):
        if self.check_options(self.essid_opt | self.canale_opt | self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'airbase-ng -c ' + self.canale + ' -e "' + self.essid + '" -N -W 1 ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Hirte attack access point mode started with ' + self.mymon)

    #
    # Start Caffe-Latte attack
    #
    def slot_wep_start_latte(self):
        if self.check_options(self.essid_opt | self.canale_opt | self.mymon_opt | self.intf_mode_opt) == 0:
            pass
        else:
            command = 'airbase-ng -c ' + self.canale + ' -e "' + self.essid + '" -L -W 1 ' + self.mymon
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Caffe_Latte attack started with ' + self.mymon)

    #
    # Start Fake Access Point
    #
    def slot_fake_ap_start(self):

        # get fake AP options
        ap_essid    = str(self.line_fake_ap_essid.text())
        ap_chan     = str(self.line_fake_ap_chan.text())
        ap_wep_key  = str(self.line_fake_ap_wep_key.text())

        ap_wep      = self.check_fake_ap_wep.isChecked()
        ap_wpa      = self.radio_fake_ap_wpa.isChecked()
        ap_wpa2     = self.radio_fake_ap_wpa2.isChecked()

        ap_adhoc      = self.check_fake_ap_adhoc_mode.isChecked()
        ap_hidden     = self.check_fake_ap_hidden_ssid.isChecked()
        ap_no_broad   = self.check_fake_ap_no_broadcast.isChecked()
        ap_rep_probes = self.check_fake_ap_all_probes.isChecked()

        # Note: 1=WEP40 2=TKIP 3=WRAP 4=CCMP 5=WEP104
        ap_wpa_type = 0
        if self.radio_fake_ap_wep40.isChecked():
            ap_wpa_type = 1
        if self.radio_fake_ap_tkip.isChecked():
            ap_wpa_type = 2
        if self.radio_fake_ap_wrap.isChecked():
            ap_wpa_type = 3
        if self.radio_fake_ap_ccmp.isChecked():
            ap_wpa_type = 4
        if self.radio_fake_ap_wep104.isChecked():
            ap_wpa_type = 5

        # check fields
        if ap_essid == "":
            self.output("no essid specified", 1)
        elif ap_chan == "":
            self.output("no channel specified", 1)
        elif self.mymon == "":
            self.output("monitor interface is not set", 1)
        elif self.intf_mode != 'Monitor':
            self.output("interface not in monitor mode", 1)
        else:
            # prepare the command
            ap_essid = ap_essid.replace(' ', '\ ')
            command = 'airbase-ng -e ' + ap_essid + ' -c ' + ap_chan
            if ap_wep:
                command += ' -W 1'
            if ap_wpa and str(ap_wpa_type) != "":
                command += ' -z ' + str(ap_wpa_type)
            if ap_wpa2 and str(ap_wpa_type) != "":
                command += ' -Z ' + str(ap_wpa_type)
            if ap_wep_key!='':
                command += ' -w ' + ap_wep_key
            if ap_adhoc:
                command += ' -A'
            if ap_hidden:
                command += ' -X'
            if ap_no_broad:
                command += ' -y'
            if ap_rep_probes:
                command += ' -P'
            command += ' ' + self.mymon

            # launch
            ct = Command_thread(command)
            ct.start()

            self.direct_output('Fake access point started with ' + self.mymon)

    #
    # Change mac address
    #
    def slot_mac_change(self):
        if self.check_options(self.change_mac_int_opt | self.change_mac_mac_opt | self.mymon_opn | self.intf_mode_opt) == 0:
            pass
        else:
            # backup of old MAC...
            commands.getstatusoutput('if [ -e ' + config_dir + '.macaddress-backup ]; then echo ""; else ifconfig ' + self.change_mac_int + ' | grep HWaddr | sed \'s/^.*HWaddr //\' > ' + config_dir + '.macaddress-backup; fi')
            status = commands.getstatusoutput('ifconfig ' + self.change_mac_int + ' down hw ether ' + self.change_mac_mac)
            if status[0] != 0:
                self.output(status[1], status[0])
                return
            status = commands.getstatusoutput('ifconfig ' + self.change_mac_int + ' up')
            if status[0] != 0:
                self.output(status[1], status[0])
                return
            self.output('Mac address of interface ' + self.change_mac_int + ' changed in ' + self.change_mac_mac, status[0])
            
    #
    # Enable ip forwarding
    #
    def slot_enable_ip_forward(self):
        command = 'echo 1 > /proc/sys/net/ipv4/ip_forward'
        ct = Command_thread(command, False)
        ct.start()

        self.direct_output('Enable IP forwarding')

    #
    # Disable ip forwarding
    #
    def slot_disable_ip_forward(self):
        command = 'echo 0 > /proc/sys/net/ipv4/ip_forward'
        ct = Command_thread(command, False)
        ct.start()

        self.direct_output('Disable IP forwarding')

    #
    # Set random MAC address
    #
    def slot_random_mac(self):

        if self.check_options(self.periferica_opt) == 0:
            return

        # disable interface
        status = commands.getstatusoutput('ifconfig '  + self.periferica + ' down')
        if status[0] != 0:
            self.output(status[1], status[0])
            return
        
        # random MAC address
        status = commands.getstatusoutput('macchanger --random '  + self.periferica)
        if status[0] != 0:
            self.output(status[1], status[0])
            return

        # re-enable interface
        status = commands.getstatusoutput('ifconfig '  + self.periferica + ' up')
        if status[0] !=0:
            self.output(status[1], status[0])
            return

        self.output("MAC Address changed: " + self.periferica, status[0])
        
        self.slot_reload_interfaces()

    #
    # Select an interface
    #
    def select_interface(self, interface):
        
        numrows = self.table_interfaces.rowCount()

        for i in range(0, numrows):
            if str(self.table_interfaces.text(i, 0)) == interface:
                self.table_interfaces.clearSelection()
                self.table_interfaces.selectRow(i)
                self.table_interfaces.repaintSelections()
                return

    #
    # Autoload interfaces
    #
    def slot_reload_interfaces(self):
        
        # clear
        numrows = self.table_interfaces.rowCount()
        for i in range(0, numrows):
            self.table_interfaces.removeRow(0)
        
        # load interfaces
        airmon = commands.getoutput("airmon-ng | egrep -e '^[a-z]{2,4}[0-9]'")
        airmon = airmon.split('\n')

        for intf in airmon:

            if intf == "":
                continue

            intf = intf.split('\t')
            # get mac address
            current_mac = commands.getoutput("ifconfig " + intf[0] + " | grep HWaddr | awk ' { print $5 } ' | tr '-' ':'")
            current_mac = current_mac[:17]
            # get mode
            mode = commands.getoutput("iwconfig " + intf[0] + " | tr ' ' '\n' | grep -i 'Mode:' | tr ':' ' ' | awk '{print $2 }'")
            # fill table
            
            
            self.table_interfaces.insertRow(0)
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(intf[0])
            self.table_interfaces.setItem(0, 0,item )
            
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(current_mac)
            self.table_interfaces.setItem(0, 1,item )
            
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(intf[2])
            self.table_interfaces.setItem(0, 2,item )
            
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText((intf[3]))
            self.table_interfaces.setItem(0, 3,item )

            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(mode)
            self.table_interfaces.setItem(0, 4,item )

        self.table_interfaces.clearSelection()


    #
    # Rescan networks
    #
    def slot_rescan_networks(self):

        if self.check_options(self.mymon_opt | self.intf_mode_opt) == 0:
            return
        
        # clear
        numrows = self.table_networks.rowCount()
        for i in range(0, numrows):
            self.table_networks.removeRow(0)

        # Prepare the command
        scan_command = 'airodump-ng --output-format csv --write /tmp/airmode-scan '
        if self.combo_channel.currentText() != 'all channels':
            scan_command = scan_command + ' --channel ' + self.combo_channel.currentText()
        scan_command = scan_command + ' ' + self.mymon
        scan_command = str(scan_command)

        # Get output from Airodump-NG
        thr = RetardedKill("airodump-ng", self.spin_sec.value())
        thr.start()
        
        status = commands.getstatusoutput(scan_command)
        if status[0] != 0:
            self.output(status[1], status[0])
        else:
            self.output("rescan networks",status[0])
        
        output_raw = commands.getoutput('cat /tmp/airmode-scan*.csv')

        # Parse output
        output     = output_raw.split("\n")
        uniq_bssid = set()
        order_id=0
        
        for out in output:
            match = re.match(r"([0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2})\s*,\s*\d{4,4}-\d{2,2}-\d{2,2}\s*\d{2,2}:\d{2,2}:\d{2,2}\s*,\s*\d{4,4}-\d{2,2}-\d{2,2}\s*\d{2,2}:\d{2,2}:\d{2,2}\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\w+)\s*,\s*([\w\s]*)\s*,\s*(\w*)\s*,\s*(.\d+)\s*,.+,\s*(.+)\s*,.*", out)

            if not match:
                continue

            bssid = match.group(1)

            if bssid in uniq_bssid:
                continue

            uniq_bssid.add(bssid)
            
            channel = match.group(2)
            mb      = match.group(3)
            enc     = match.group(4)
            cipher  = match.group(5)
            auth    = match.group(6)
            pwr     = match.group(7)
            essid   = match.group(8)

            self.table_networks.insertRow(order_id)
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(QtGui.QApplication.translate("Main_window", essid, None, QtGui.QApplication.UnicodeUTF8))
            self.table_networks.setItem(order_id, 0,item )
            item=QtGui.QTableWidgetItem(bssid)
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(bssid)
            self.table_networks.setItem(order_id, 1,item)
        
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(channel)
            self.table_networks.setItem(order_id, 2,item)
        
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(pwr)
            self.table_networks.setItem(order_id, 3,item)
        
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(enc + ' ' + cipher + ' ' + auth)
            self.table_networks.setItem(order_id, 4, item)
        
            item=QtGui.QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsEnabled)
            item.setText(mb)
            self.table_networks.setItem(order_id, 5,item)

            order_id=order_id+1

        self.table_networks.clearSelection()
        commands.getstatusoutput('rm /tmp/airmode-scan*')

    #
    # Autoload victim clients
    #
    def slot_autoload_victim_clients(self):
        
        # clear
        self.combo_wep_mac_cfrag.clear()
        self.combo_wpa_mac_hand.clear()

        # check *.csv files
        if not glob.glob(config_dir + "*.csv"):
            self.output("no csv files in " + config_dir, 1)
            return
        
        # open dump file
        dump_file = commands.getoutput("cat " + config_dir + "*.csv | egrep -e '^[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}.+[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2},' | grep " + self.ac + " | tr ',' ' ' | awk ' { print $1 } '")
        dump_file = dump_file.split('\n')        
        
        for mac in dump_file:
            self.combo_wep_mac_cfrag.insertItem(0, mac)
            self.combo_wpa_mac_hand.insertItem(0, mac)

    #
    # Add cracked key to database
    #
    def add_key_to_database(self):
        aircrack_log = config_dir + 'aircrack-log.txt'

        # read cracked key
        key = commands.getoutput("cat " + aircrack_log + " | grep 'KEY FOUND' | tr '[]' '\n' | egrep '([a-fA-F0-9]:)+' | tr -d ' \t'")
 
        # insert a row in the database
        self.table_database.insertRow(0)
        item=QtGui.QTableWidgetItem()
        item.setText(essid)
        self.table_database.setItem(0, 0, item)
    
        item=QtGui.QTableWidgetItem()
        item.setText(self.ac)
        self.table_database.setItem(0, 1, item)
    
        item=QtGui.QTableWidgetItem()
        item.setText(self.canale)
        self.table_database.setItem(0, 2, item)
    
        item=QtGui.QTableWidgetItem()
        item.setText(key)
        self.table_database.setItem(0, 3, item)
    
        item=QtGui.QTableWidgetItem()
        item.setText((key_to_ascii(key)))
        self.table_database.setItem(0, 4, item)
        
        
    #
    # Database changed
    #
    def slot_database_changed(self):
        selrow = self.table_database.currentRow()
        if selrow == -1:
            return

        key = str(self.table_database.item(selrow, 3))
    
        item=QtGui.QTableWidgetItem()
        item.setText((key_to_ascii(key)))
        self.table_database.setItem(selrow, 4, item)

    #
    # Add an entry to the database table
    #
    def slot_database_add(self):
        self.table_database.insertRow(0)


    #
    # Delete an entry from the database table
    #
    def slot_database_delete(self):

        selrow = self.table_database.currentRow()
        if selrow == -1:
            return

        self.table_database.removeRow(selrow)

    #
    # Reload the database
    #
    def slot_database_reload(self):

        # open the database and a cursor
        try:
            self.database_connection = sqlite3.connect(self.database)
            c = self.database_connection.cursor()
        except:
            self.output("Error loading database: " + self.database, 1)
            return

        # create table if not exists
        c.execute('''create table if not exists keys (essid text, bssid text, channel text, key text)''')

        # clear GUI table
        numrows = self.table_database.rowCount()
        for i in range(0, numrows):
            self.table_database.removeRow(0)

        # read and fill database table
        c.execute('select * from keys order by essid desc')
        for row in c:
            essid   = row[0]
            bssid   = row[1]
            channel = row[2]
            key     = row[3]
            ascii   = key_to_ascii(key)

            self.table_database.insertRow(0)
        
            item=QtGui.QTableWidgetItem()
            item.setText(essid)
            self.table_database.setItem(0, 0, item)
        
            item=QtGui.QTableWidgetItem()
            item.setText(bssid)
            self.table_database.setItem(0, 1, item)
        
            item=QtGui.QTableWidgetItem()
            item.setText(channel)
            self.table_database.setItem(0, 2, item)
        
            item=QtGui.QTableWidgetItem()
            item.setText(key)
            self.table_database.setItem(0, 3, item)
        
            item=QtGui.QTableWidgetItem()
            item.setText(ascii)
            self.table_database.setItem(0, 4, item)

        # close the cursor
        c.close()

        self.output("database reloaded: " + self.database, 0)

    #
    # Save the database
    #
    def slot_database_save(self):

        # open cursor
        try:
            self.database_connection = sqlite3.connect(self.database)
            c = self.database_connection.cursor()
        except:
            self.output("Error loading database: " + self.database, 1)
            return

        # clear database
        c.execute('''drop table keys''')
        c.execute('''create table keys (essid text, bssid text, channel text, key text)''')

        # read GUI table
        numrows = self.table_database.rowCount()
#        self.periferica = str((self.table_interfaces.item(selrow, 0)).text())
        for i in range(0, numrows):
            essid   = str((self.table_database.item(i, 0)).text())
            bssid   = str((self.table_database.item(i, 1)).text())
            channel = str((self.table_database.item(i, 2)).text())
            key     = str((self.table_database.item(i, 3)).text())

            c.execute("insert into keys values ('" + essid + "', '" + bssid + "', '" + channel + "', '" + key + "')")

        # commit and close
        try:
            self.database_connection.commit()
            c.close()
        except:
            c.close()
            self.output("Error saving database: " + self.database, 1)
            return
 
        
        self.output("database saved: " + self.database, 0)


    #
    # Callbacks for input field text changes
    # updates automagically the global variables...
    #

    def slot_gath_int(self):
        self.periferica = str(self.combo_gath_int.currentText())

    def slot_interface_selected(self):
        selrow = self.table_interfaces.currentRow()
        
        if selrow == -1:
            self.periferica = ''
            self.mymon      = ''
            self.mymac      = ''
            self.intf_mode  = ''
            return

        self.periferica = str((self.table_interfaces.item(selrow, 0)).text())
        self.mymon      = str((self.table_interfaces.item(selrow, 0)).text())
        self.mymac      = str((self.table_interfaces.item(selrow, 1)).text())
        self.intf_mode  = str((self.table_interfaces.item(selrow, 4)).text())
        
        #self.change_mac_int = self.mymon
        #self.line_mac_change_int.setText(self.mymon)
        #self.change_mac_mac = self.mymac 
        #self.line_mac_change_mac.setText(self.mymac )

    def slot_network_selected(self):
        selrow = self.table_networks.currentRow()
        if selrow == -1:
            return

        self.essid  = str((self.table_networks.item(selrow, 0)).text())
        self.ac     = str((self.table_networks.item(selrow, 1)).text())
        self.canale = str((self.table_networks.item(selrow, 2)).text())

        #print self.essid + " " + self.ac + " " + self.canale
    
    def slot_line_database(self):
        self.database = str(self.line_database.text())

    def slot_line_crack_wpa_dictionary(self):
        self.dfile = str(self.line_crack_wpa_dictionary.text())

    def slot_line_crack_wpa_dictionary_pyrit(self):
        self.dfile2 = str(self.line_crack_wpa_dictionary_pyrit.text())

    def slot_line_crack_wpa_rainbow_tables_file(self):
        self.rtablesfile1 = str(self.line_crack_wpa_rainbow_tables_file.text())

    def slot_line_gath_logs(self):
        self.config_dir = str(self.line_gath_logs.text())

    def slot_line_mac_change_int(self):
        self.change_mac_int = str(self.line_mac_change_int.text())

    def slot_line_mac_change_mac(self):
        self.change_mac_mac = str(self.line_mac_change_mac.text())

    def slot_line_wep_mac_cfrag(self):
        self.ac_victim = str(self.combo_wep_mac_cfrag.currentText())

    def slot_line_wpa_mac_hand(self):
        self.ac_victim_wpa = str(self.combo_wpa_mac_hand.currentText())

    def slot_line_wpa_deauth_hand(self):
        self.deauth_WPA_num = str(self.spin_wpa_deauth_hand.text())

    def slot_spin_wep_wireless_req(self):
        self.mval = str(self.spin_wep_wireless_req.value())

    def slot_spin_wep_wired_req(self):
        self.nval = str(self.spin_wep_wired_req.value())

    #
    # Initializer
    #
    def init(self):
        pass

    #
    # Fill input fields on program load
    #
    def fill_input_fields(self):

        # variables/gui input fields
        self.periferica         = ''
        self.periferica_opt     = 1 << 0

        self.mymon              = ''
        self.mymon_opt          = 1 << 1

        self.mymac              = ''
        self.mymac_opt          = 1 << 2

        self.ac                 = ''
        self.ac_opt             = 1 << 3

        self.canale             = ''
        self.canale_opt         = 1 << 4

        self.essid              = ''
        self.essid_opt          = 1 << 5

        self.mval               = '68'
        self.mval_opt           = 1 << 6

        self.nval               = '86'
        self.nval_opt           = 1 << 7

        self.ac_victim          = ''
        self.ac_victim_opt      = 1 << 8

        self.ac_victim_wpa      = ''
        self.ac_victim_wpa_opt  = 1 << 9

        self.deauth_WPA_num     = ''
        self.deauth_WPA_num_opt = 1 << 10

        self.dfile              = ''
        self.dfile_opt          = 1 << 11

        self.dfile2             = ''
        self.dfile2_opt         = 1 << 12

        self.change_mac_int     = ''
        self.change_mac_int_opt = 1 << 13

        self.change_mac_mac     = ''
        self.change_mac_mac_opt = 1 << 14

        self.rtablesfile1       = ''
        self.rtablesfile1_opt   = 1 << 15

        self.intf_mode          = ''
        self.intf_mode_opt      = 1 << 16

        # Database
        self.database = database_path;
        self.line_database.setText(self.database)
        try:
            self.database_connection = sqlite3.connect(self.database)
        except:
            pass
        self.slot_database_reload()

        # Session file directory
        self.line_gath_logs.setText(config_dir)

        # Wireless interfaces
        self.slot_reload_interfaces()
        print "interface reloaded"      
        if selected_interface != '':
			print "interface not empty"
			self.periferica = selected_interface
			print "selecting "+selected_interface
			self.select_interface(selected_interface)
            

        # Various directories
        self.line_crack_wpa_dictionary.setText(home_dir)
        self.line_crack_wpa_dictionary_pyrit.setText(home_dir)
        self.line_crack_wpa_rainbow_tables_file.setText(home_dir)

        # WPA deauth
        self.slot_line_wpa_deauth_hand()

        # Tables
        self.table_interfaces.clearSelection()
        self.table_networks.clearSelection()


#
# This function initialize the config directory
#
def init_config_dir():
    global def_term

    # check config dir
    if not os.path.exists(config_dir):
        os.mkdir(config_dir)    
        #subprocess.getstatusoutput('zenity --info --window-icon=/usr/local/buc/icons/attenzione.png --title="AirMode" --text="Hello and Thanks for using AirMode this is the first run, and ~/.airmode is now created."')

    print ('\nConfig directory OK\n')

#
# This function perform various checks
# on program load
#
def check_all():

    # check for root uid
    if not os.geteuid()==0:
        main_window.direct_output('<b>Error:</b> <font color="#ff0000">You should run this program as root! ;-D</font>')



#
# MAIN FUNCTION
# The program starts here
#
if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    ui = Main_window_ex()
   
# initialize config directory
    init_config_dir()

# change working directory
    os.chdir(config_dir)
	
# performs various checks
    check_all()
 
# config init function
    config_init()
# config end function
    config_end() 

# fill the GUI
    
    ui.fill_input_fields()  

#    ui.fill_input_fields()
    ui.show()
    sys.exit(app.exec_())



 




