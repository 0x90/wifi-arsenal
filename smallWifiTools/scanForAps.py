#!/usr/bin/python

import sys
import sqlite3
from scapy.all import *

aps = set()

def packetHandler(packet):
	if packet.haslayer(Dot11Beacon):
		newCombination = packet.info + " " + packet.addr2
		if newCombination not in aps:
			aps.add(newCombination)
			print str(len(aps)) + ": " + packet.addr2 + " --> Accesspoint name: " + packet.info

connection = sqlite3.connect("wifi.db")
sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=packetHandler)
for ap in aps:
	[apname, mac] = ap.split(" ")
	statement = "INSERT INTO accesspoints (location, macaddress, apname) VALUES (\"" + sys.argv[3] + "\", \"" + mac + "\", \"" + apname + "\")"
	connection.execute(statement)
	connection.commit()
connection.close()
