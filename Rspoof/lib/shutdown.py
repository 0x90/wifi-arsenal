#!/usr/bin/env python
# -*- coding: Utf-8 -*-

# shutdown.py
# A script to shutdown all attacks for rspoof and reset the system.
# Scripted for Kali Linux GNOME x64


import subprocess
from config.core import *

def Clean_Exit():
    subprocess.Popen("killall -I -q 'airbase-ng'", shell=True).wait()
    subprocess.Popen("iptables -t nat -F", shell=True).wait()
    subprocess.Popen("iptables -t nat -X", shell=True).wait()
    subprocess.Popen("iptables -t nat -Z", shell=True).wait()
    subprocess.Popen("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True).wait()
    reset_ifaces()

def reset_ifaces():
    subprocess.Popen("rfkill block all;rfkill unblock all", shell=True).wait()
    subprocess.Popen("ifconfig %s down" % PRIMARY_WLAN_INTERFACE, shell=True).wait()
    subprocess.Popen("ifconfig %s down" % SECONDARY_WLAN_INTERFACE, shell=True).wait()
    subprocess.Popen("ifconfig %s up" % PRIMARY_WLAN_INTERFACE, shell=True).wait()
    subprocess.Popen("ifconfig %s up" % SECONDARY_WLAN_INTERFACE, shell=True).wait()



