#!/usr/bin/python

import sys
import sqlite3
from scapy.all import *

clientProbes = set()

def packetHandler(packet):
	# it is a probe request
	if packet.haslayer(Dot11ProbeReq):
		if len(packet.getlayer(Dot11ProbeReq).info) > 0:
			newCombination = packet.getlayer(Dot11).addr2 + " " + packet.getlayer(Dot11ProbeReq).info
			if newCombination not in clientProbes:
				clientProbes.add(newCombination)
				print str(len(clientProbes)) + ": " + packet.getlayer(Dot11).addr2 + " --> " + packet.getlayer(Dot11ProbeReq).info

connection = sqlite3.connect("wifi.db")
# start sniffer
sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=packetHandler)
# save data into database
for probe in clientProbes:
	[mac, ssid] = probe.split(" ")
	statement = "insert into clientProbes (location, macaddress, ssid) values (\"" + sys.argv[3] + "\", \"" + mac + "\", \"" + ssid + "\")"
	connection.execute(statement)
	connection.commit()
connection.close()
