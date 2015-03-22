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

import struct, time, pipes, subprocess

import PyLorcon2
from pcapy import open_live, PcapError

from config import *

class SendRec:
	"""
	
	Main IO functionality of bunny, using pcapy and lorcon to do send and receive.
	
	"""

		# Helper functions for modifiing the state of the iface. 
	def setmonitor(self, iface, monitor=True):
		mode = "monitor"
		if not monitor:
			mode = "managed"

		# I don't like this, it feels hacky
		subprocess.call(["ifconfig", pipes.quote(iface), "down"])
		subprocess.call(["iwconfig", pipes.quote(iface), "mode", mode])
		subprocess.call(["ifconfig", pipes.quote(iface), "up"])


	def __init__(self):
		try:
			self.lorcon = PyLorcon2.Context(IFACE)
		except PyLorcon2.Lorcon2Exception as err:
			print "Error creating lorcon object: "
			print str(err)
			exit()
		
		self.setmonitor(IFACE, monitor=True)
		try:
			self.lorcon.open_injmon()
		except PyLorcon2.Lorcon2Exception as err:
			print "Error while setting injection mode, are you root?"
			print str(err)
			exit()

		self.lorcon.set_channel(CHANNEL)
		
		
		# Quick definitions for pcapy
		MAX_LEN      = 1514		# max size of packet to capture
		PROMISCUOUS  = 1		# promiscuous mode?
		READ_TIMEOUT = 0		# in milliseconds, I found that 0 does not tend to block
								#  in the way I had assumed and you get a NULL pcap error from:
								#  https://github.com/CoreSecurity/pcapy/blob/master/pcapobj.cc#L215
		MAX_PKTS     = 1		# number of packets to capture; 0 => no limit
		
		try:
			self.pcapy = open_live(IFACE, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
		except PcapError as err:
			print "Error creating pcapy descriptor, try turning on the target interface or setting it to monitor mode"
			print str(err)
		
	def updateChan(self, channel):
		"""
		
		Updates the current channel
		
		"""
		self.lorcon.set_channel(channel)
	
	# These send/rec functions should be used in hidden / paranoid mode.
	def sendPacket(self, data):
		if data is not None:
			try:
				self.lorcon.send_bytes(data)
			except PyLorcon2.Lorcon2Exception as err:
				print "ERROR sending packet: "
				print str(err)
	def recPacket_timeout(self, fcs):
		"""
		return the raw packet if the mod/remain value is correct. 
		returns False upon a timeout
		
		"""
		start_t = time.time()
		while(time.time() - start_t < TIMEOUT):
			try:
				header, rawPack = self.pcapy.next()
			except PcapError:
				# This exists because on some hardware, instead of blocking for a packet
				#  the pcap layer will return a null packet buffer and no error message.
				continue
				
			if rawPack is None:
				continue
			# H = unsigned short
			size = struct.unpack("<H", rawPack[2:4])
			size = int(size[0])
			
			# check if the radio tap header is from the interface face itself (loop backs)
			#  that '18' might need to change with different hardware and software drivers
			if size >= 18:
				rawPack = rawPack[size:]
				size = len(rawPack)
				# subtract the FCS to account for the radiotap header adding a CRC32
				if (round( (size - fcs) % MODULUS, 2) == REMAINDER):
					return rawPack
		else:
			return False
	
	def reloop(self):
		"""
		This exists only for testing purposes.
		To ensure proper packets are read properly and at a high enough rate. 
		"""
		count = 0
		packNum = 200
		startTime = time.time()
		for n in range(packNum):
			header, rawPack = self.pcapy.next()
			if rawPack is None:
				continue
			# H = unsigned short
			size = struct.unpack("<H", rawPack[2:4])
			size = int(size[0])
			
			# check if the radio tap header is from the interface face itself (loop backs)
			#  that '18' might need to change with different hardware and software drivers
			if size >= 18:
				rawPack = rawPack[size:]
				size = len(rawPack)
				# subtract the FCS to account for the radiotap header adding a CRC32
				if (round( (size - 4) % MODULUS, 2) == REMAINDER):
					print "pack num: %d, " % n  
		endTime = time.time()
		totalTime = endTime - startTime
		packPerSec = packNum / totalTime
		print "Total Packets (p/s): %s" % packPerSec

	def recvRaw(self):
		""" Returns packet	
		
		RadioTap headers included
		
		"""
		while True:
			try:
				header, rawPack = self.pcapy.next()
			except PcapError:
				# This exists because on some hardware, instead of blocking for a packet
				#  the pcap layer will return a null packet buffer and no error message.
				continue

			if rawPack is None:
				if DEBUG:
					print 'got a nothing packet, possible issue with pcapy that is mentioned in README'

			return rawPack

	def close(self):
		""" 
		Clean things up
		"""
		self.lorcon.close()
		self.setmonitor(IFACE, monitor=False)