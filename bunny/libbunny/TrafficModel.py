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

import time, struct, operator, binascii, random

# This is indicative of object reuse. 
from SendRec import *
from Templates import *

class TrafficModel():
	"""
	
	Builds a model of current traffic that can be used at a later time to make packets.
	
	"""
	# In network byte order
	# If you do a lookup on this table and dont find a match it is probly
	# a 'reserved' type.
	Dot11_Types = {
		# management
		"assocReq": "\x00",
		"assocRes": "\x10",
		"reAssocReq": "\x20",
		"reAssocRes": "\x30",
		"probeReq": "\x40",
		"probeRes": "\x50",
		"beacon": "\x80",
		"ATIM": "\x90",
		"disAssoc": "\xa0",
		"auth": "\xb0",
		"deAuth": "\xc0",
		"action": "\xd0",

		# control
		"blockAckReq": "\x81",
		"blockAck": "\x91",
		"PSPoll": "\xa1",
		"RTS": "\xb1",
		"CTS": "\xc1",
		"ACK": "\xd1",
		"ACK2": "\xd4",
		"CFend": "\xe1",
		"CFendCFack": "\xf1",

		# data
		"data": "\x02",
		"data-CFAck": "\x12",
		"data-CFPoll": "\x22",
		"data-CFAckPoll": "\x32",
		"dataNULL": "\x42",
		"dataNULLfunc": "\x48",
		"data-CFAckNULL": "\x52",
		"data-CFPollNULL": "\x62",
		"data-CFAckPollNULL": "\x72",
		"dataQOS": "\x82",
		"dataQOS2": "\x88",
		"dataQOS-CFAck": "\x92",
		"dataQOS-CFPoll": "\xa2",
		"dataQOS-CFAckPoll": "\xb2",
		"dataQOSNULL": "\x82",  # wtf why?
		"dataQOS-CFPollNULL": "\xe2",
		"dataQOS-CFAckPollNULL": "\xf2",
	}
	
	# Model attributes:
	# -Type ranges
	# -MAC addresses
	# -
	# raw packets
	data = []
	
	# [type, freq, template, injectlen]
	type_ranges = []
	
	# [addr, freq, AP(bool)]
	mac_addresses = []
	
	# FCS is the number of bytes for the Checksum if it is found in stripRadioTap()
	FCS = 0
	
	def __init__(self):
		"""
		
		Starts up the model, collects data and inserts it into its respective lists
		
		"""
		# clear any old data
		self.mac_addresses = []
		self.type_ranges = []
		self.data = []
		
		# spin up and build the model
		self.interface = SendRec()
		self.collectData()
		self.stripRadioTap()
		self.extractModel()
		self.insertTemplates()
			
	def collectData(self):
		"""
		
		Collect packets for the pre determined amount of time.
		
		"""
		start_time = time.time()
		current_time = start_time
		
		# caplength is a glocal var from config.
		while ( (current_time - start_time) < CAPLENGTH):
			packet = self.interface.recvRaw()
			self.data.append(packet)
			current_time = time.time()
	
	def stripRadioTap(self):
		"""
		Strips the RadioTap header info out of the packets are replaces the data 
		list with the new packets.
		
		It also checks if this hardware has FCS (Frame Check sums's) at the end
		"""
		temp_data = []
		
		# Check for FCS flag in the radiotap header
		flags = self.data[0][4:8]
		flags = struct.unpack("i", flags)[0]

		#	  bval         idx 
		if ((flags & (1 << 0)) != 0):
			subflags = self.data[0][16:17]
			subflags = struct.unpack("B", subflags)[0]
		else:
			subflags = self.data[0][8:9]
			subflags = struct.unpack("B", subflags)[0]
		
		if ((flags & (1 << 1)) != 0):
			if ((subflags & (1 << 4)) != 0):
				self.FCS = 4
		
		if DEBUG:
			print "FCS: %s" % (self.FCS)
		#  now strip the headers.
		for packet in self.data:
			sizeHead = struct.unpack("<H", packet[2:4])
			temp_data.append(packet[sizeHead[0]:])
		self.data = temp_data
	
	def rawToType(self, type_raw):
		"""
		
		input the byte and return a string of the 802.11 type
		
		"""
		for k,v in self.Dot11_Types.iteritems():
			if (v == type_raw[0]):
				return k
		return "reserved (" + binascii.hexlify(type_raw[0]) + ")"
	
	def buildModelTypes(self, graphs):
		"""
		
		Adds the extracted types and %'s to the model
		
		"""
		count = 0.0
		for type in graphs:
			count += type[1]
		for type in graphs:
			type[1] = (type[1] / count)
			self.type_ranges.append(type)
					
	def buildModelAddresses(self, addresses):
		""""
		
		Adds the extracted addresses and %'s to the model
		
		"""
		count = 0.0
		for addr in addresses:
			count += addr[1]
		for addr in addresses:
			addr[1] = (addr[1] / count)
			self.mac_addresses.append(addr)
			
	def extractModel(self):
		"""
		
		Loops through all collected packets and creates different aspects of the model
		
		"""
		graphs = []
		addresses = []
	
		# loop through all packets, then loop through all types,
		# append if the type is not found,
		# inrement count if it is.
		for packet in self.data:
			beacon = False
			
			# graphs[type, count]
			type = packet[:1]
			
			# check if its a beacon packet
			if(type == self.Dot11_Types['beacon']):
				beacon = True
			found = False
			for types in graphs:
				if (type == types[0]):
					types[1] = types[1] + 1
					found = True
			if(found == False):
				graphs.append([type, 1, packet, 0])
			
			
			# addresses[addr, count, AP?]
			# model common mac addresses used
			mac = packet[10:15]
			
			found = False
			for addr in addresses:
				if (mac == addr[0]):
					addr[1] = addr[1] + 1
					found = True
			if(found == False):
				if (beacon == True):
					addresses.append([mac, 1, True])
				else:
					addresses.append([mac, 1, False])
		
		# sort by count		
		graphs.sort(key=operator.itemgetter(1), reverse=True)
		addresses.sort(key=operator.itemgetter(1), reverse=True)
		
		self.buildModelTypes(graphs)
		self.buildModelAddresses(addresses)
		
	def insertTemplates(self):
		"""
		
		loops through the type_ranges list and replaces the raw packet data with template objects
		type_ranges becomes:
		[type, freq, templateObject, injectLen]
		
		"""
		tmp_list = []
		for entry in self.type_ranges:
			if entry[0] is None:
				continue
			type = self.rawToType(entry[0])
			if (type == "beacon"):
				# replace raw data with object of template type, then append the injection length
				entry[2] = Templates.Beacon(entry[2])
			elif (type == "data" or type == "dataQOS" or type == "dataQOS2"):
				entry[2] = Templates.DataQOS(entry[2])
			elif (type == "probeReq"):
				entry[2] = Templates.ProbeRequest(entry[2])
			else:
				continue
			tmp_list.append(entry)
		self.type_ranges = tmp_list

	def insertNewTemplate(self, raw_packet):
		"""
		
		This is a copy past of the insertTemplate() func but does not loop through, instead
		a raw_packet is passed in as an argument then, then this function finds its type and inserts
		it, if an corresponding Template exists
		
		returns false if the packet type does not have a template
		returns the entry in type_ranges[] if found
		
		TODO: Currently only lets this bunny instance READ 
		with this packet type because there is zero frequency.
		"""
		entry = [0, 0, 0]
		
		raw_type = raw_packet[:1]
		type = self.rawToType(raw_type)
		
		if (type == "beacon"):
			# replace raw data with object of template type, then append the injection length
			entry[0] = raw_type
			entry[2] = Templates.Beacon(raw_packet)
		elif (type == "data" or type == "dataQOS" or type == "dataQOS2"):
			entry[0] = raw_type
			entry[2] = Templates.DataQOS(raw_packet)
		elif (type == "probeReq"):
			entry[0] = raw_type
			entry[2] = Templates.ProbeRequest(raw_packet)
		else:
			entry = False
		
		return entry
		
	# debugging:
	def printTypes(self):
		"""
		
		Prints out a list of the packet types and percentages in the model
		
		"""
		print "%-15s%s" % ("Type", "Percent")
		print "-" * 20
		for entry in self.type_ranges:
			print "%-15s%f" % (self.rawToType(entry[0]), entry[1])

	def printTypesWithPackets(self):
		"""
		
		Prints out a list of the packet types and percentages in the model
		
		"""
		print "%-15s%-10s%s" % ("Type", "Percent", "Template")
		print "-" * 30
		for entry in self.type_ranges:
			print "%-15s%-10f%s" % (self.rawToType(entry[0]), entry[1], binascii.hexlify(entry[2]))

	def printMacs(self):
		"""
		
		Prints out a list of src mac address and percentages in the model
		
		"""
		print "\n%-15s%-10s%s" % ("Addr", "Percent", "AP")
		print "-" * 30
		for entry in self.mac_addresses:
			print "%-15s%-10f%s" % (binascii.hexlify(entry[0]), entry[1], entry[2])

	def getEntry(self):
		"""
		
		Returns a frequency adjusted random entry from the array type_ranges
		Follows the [name, freq, ...] structure.
		
		"""
		num = random.random()
		count = 0.0
		for entry in self.type_ranges:
			count += entry[1] 
			if count > num:
				break
		return entry
