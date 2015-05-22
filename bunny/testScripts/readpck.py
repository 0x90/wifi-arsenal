#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    bunny.py
#
#    Copyright 2013 W. Parker Thompson <w.parker.thompson@gmail.com>
#		
#    This file is part of Bunny.
#
#    Bunny is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Bunny is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Bunny.  If not, see <http://www.gnu.org/licenses/>.

import binascii
import struct
import time

from pcapy import open_live

IFACE = "wlan2"
MAX_LEN      = 1514		# max size of packet to capture
PROMISCUOUS  = 1		# promiscuous mode?
READ_TIMEOUT = 0		# in milliseconds
MAX_PKTS     = 1		# number of packets to capture; 0 => no limit
try:
	pcapy = open_live(IFACE, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
except:
	print "Error creating pcapy descriptor, try turning on the target interface or setting it to monitor mode"

cnt = 0

start_t = time.time()
while(time.time() - start_t < 5):
	header, rawPack = pcapy.next()
	# H = unsigned short
	size = struct.unpack("<H", rawPack[2:4])
	size = int(size[0])
	
	# check if the radio tap header is from the interface face itself (loop backs)
	#  that '18' might need to change with different hardware and software drivers
	if size >= 18:
		rawPack = rawPack[size:]
		size = len(rawPack)
		# subtract the FCS to account for the radiotap header adding a CRC32
		if (round( (size - 4) % 1.21, 2) == 0.85):
			#print "got packet"
			cnt = cnt + 1
	
print cnt
