#!/usr/bin/env python
# -*- coding: utf-8 -*-
from subprocess import Popen, call, PIPE
import os
#from sys import stdout, stdin # Flushing
import re
import logging

#logging.basicConfig(level=logging.DEBUG,
#                    format='%(asctime)s %(levelname)s %(filename)s: %(message)s',
#                    datefmt='%Y-%m-%d %H:%M:%S')

DN = open(os.devnull, 'w')

def enable_monitor_mode(iface=''):
    #First, disable all existing monitor interfaces
    disable_monitor_mode()
    #If not specified, take the last wireless interface.		
    if not iface:
        proc  = Popen(['airmon-ng'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if 'phy' in line and not line.startswith("mon"):
                    iface=re.split(r"\s",line)[0]
    if iface:
        logging.debug("Enabling monitor mode on '%s'"%iface)
        call(['airmon-ng', 'check', 'kill'], stdout=DN, stderr=DN)
        call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
        monif = get_monitor_iface()
        if monif:
            logging.debug("Enabled monitor mode '%s'"%monif[0])
            return monif[0]
    else:
        logging.debug("No wireless interface supporting monitor mode found")
        return None

def disable_monitor_mode(iface=''):
    #Disable all monitor interfaces
    if not iface:
        for device in get_monitor_iface():
            disable_monitor_mode(device)
            #call(['airmon-ng', 'stop', device], stdout=DN, stderr=DN)
    else:
        logging.debug("Disabling monitor mode on '%s'"%iface) 
        call(['airmon-ng', 'stop', iface], stdout=DN, stderr=DN)

def get_monitor_iface():
    proc  = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    iface = ''
    monitors = []
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue
        if ord(line[0]) != 32: # Doesn't start with space
            iface = line[:line.find(' ')] # is the interface
            if line.find('Mode:Monitor') != -1:
                monitors.append(iface)
    return monitors
