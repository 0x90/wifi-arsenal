#!/usr/bin/python

import sys
from scapy.all import *
import random
import string

for x in range(0, int(sys.argv[2])):
	# generate mac address randomly
	firstbyte = hex(random.randint(0, 255))[2::]
	secondbyte = hex(random.randint(0, 255))[2::]
	thirdbyte = hex(random.randint(0, 255))[2::]
	fourthbyte = hex(random.randint(0, 255))[2::]
	fifthbyte = hex(random.randint(0, 255))[2::]
	sixthbyte = hex(random.randint(0, 255))[2::]
	macaddr = firstbyte + ":" + secondbyte + ":" + thirdbyte + ":" + fourthbyte + ":" + fifthbyte + ":" + sixthbyte

	# generate SSID
	randomString = [random.choice(string.ascii_letters) for n in xrange(10)]
	randomSSID = "".join(randomString)
	
	# send packet
	print "Sending beacon frames for SSID:", randomSSID, " on channel: 8\n"
	pkt = RadioTap()/Dot11(subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=macaddr, addr3=macaddr)/Dot11Beacon(timestamp=0, beacon_interval=100)/Dot11Elt(ID=0, info=randomSSID)/Dot11Elt(ID=1, info="\x82\x84\x8b\x96")/Dot11Elt(ID=3, len=1, info="\x08")/Dot11Elt(ID=4, len=6, info="\x01\x02\x00\x00\x00\x00")/Dot11Elt(ID=5, len=4, info="\x00\x01\x00\x00")
	sendp(pkt, iface=sys.argv[1], count=100, inter=0.01)
