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

import struct, random, os

from config import *

def generate_seqnumb():
	return struct.pack("<H", random.randrange(0,65536) & 0xF000)

class Templates:
	"""
	
	Contains templates for all packet types used by bunny.
	
	"""
	class Beacon:
		"""
		
		Template for Beacon packet types.  Initialize the template with a raw packet dump 
		of a beacon packet.
		
		"""
		# declares the number of bytes of communication this template can hold for a single injection
		injectable = 0
		
		type = ""
		frame_control = ""
		duration = ""
		BSSID = ""
		SA = ""
		DA = ""
		sequence_num = ""
		QOS = ""
		
		timestamp = ""
		beacon_interval = ""
		capability = ""
		
		# an array for taged fields 
		# tag [tagID, length, value]
		tags = []
		
		# a list of vendors found
		vendors = []
		
		SSID = ""

		def __init__(self, packet):
			# For a speed up we could use the struct.unpack() method
			#self.type, self.frame_control, struct.unpack("", pack_data)
			self.type = packet[0:1]
			self.frame_control = packet[1:2]
			self.duration = packet[2:4]
			self.BSSID = packet[4:10]
			self.SA = packet[10:16]
			self.DA = packet[16:22]
			self.sequence_num = packet[22:24]
			#self.RS = packet[21:26]
			self.timestamp = packet[24:32]
			self.beacon_interval = packet[32:34]
			self.capability = packet[34:36]
			
			packet = packet[36:]
			
			# Simple command to debug the current var's of this object.
			# print self.__dict__.keys()
			
			# loop through the tags and SAP them off into in the tags array
			# also appends any vendor OUI's into the vendors list.
			
			# this might be the place we have an error with comp to comp sending.
			# due to the fact it tries read past the end of the.
			while (len(packet) >= 4):
				id = packet[:1]
				length, = struct.unpack("B", packet[1:2])
				value = packet[2:length+2]
				self.tags.append([id, length, value])
				if id == "\xdd":
					self.vendors.append([value[:3]])
				packet = packet[length + 2:]
				
			#self.SSID = self.tagGrabber("\x00")
			
			# design problem here, after attempting dynamic lengths for the injection
			# fields I relized that for interconnectivity between clients I need to hardcode
			# injection lengths.  So the vendor tag is 24 bytes of data:
			self.injectable = 26 + 2
			
		def makePacket(self, inject_data):
			"""
			
			Creates and returns a beacon packet from the inject_data input
			inject_data must be of length Beacon.injectable
			
			injectable fields are:
			capabilities, 2nd to last vendor tags.
			
			NOTE: sequence_num had to be removed due to an issue with the AR9271 firmware, see:
				https://github.com/qca/open-ath9k-htc-firmware/issues/16
			
			"""

			self.sequence_num = generate_seqnumb()

			# timestamp needs more testing.
			outbound = self.type + self.frame_control + self.duration + self.BSSID + self.SA + self.DA + self.sequence_num + self.timestamp + self.beacon_interval + inject_data[0:2]
			
			for i in range(0, len(self.tags)-2):
				outbound = outbound + self.tags[i][0] + struct.pack("<B", self.tags[i][1]) + self.tags[i][2]
			outbound = outbound + "\xdd" + struct.pack("<B", len(inject_data[2:])) + inject_data[2:]
			#outbound += struct.pack("!i", zlib.crc32(outbound))
			
			outbound = self.resize(outbound)
			#print "len of injectedBEACON: %d" % len(inject_data)
			return outbound
		def resize(self, outpack):
			"""
			
			Resizes the packet with the proper mod / REMAINDER value
			
			Primarly uses last vendor tag.
			
			"""
			# counter will be the size of the tag
			# using \xdd for vendor tag.
			#print self.vendors
			if len(self.vendors) > 0:
				tag = ["\xdd", 0, self.vendors[random.randrange(0, len(self.vendors))][0]]
			else:
				tag = ["\xdd", 0, ""]
			
			#while( round((len(outpack) + tag[1] + 2 + RADIOTAPLEN) % MODULUS, 2) != REMAINDER):
			while( round((len(outpack) + tag[1] + 2) % MODULUS, 2) != REMAINDER):
				tag[2] = tag[2] + os.urandom(1)
				tag[1] = len(tag[2])
			
			# + 4 if for eating the checksum that for w/e reason gets parsed as a tag.	
			outpack = outpack + tag[0] + struct.pack("B", tag[1]) + tag[2]
			
			return outpack
		
		def decode(self, input):
			
			# sequence num
			#output = input[22:24]
			
			# capabilities.
			output = input[34:36]
			
			temp_tags = []
			input = input[36:]
			data_size = len(input)
			
			# protect from non-Bunny packets
			if data_size < 4:
				return False
				
			# loop through and grab the second to last vendor tag
			while (len(input) >= 4):
				id = input[:1]
				length, = struct.unpack("B", input[1:2])
				value = input[2:length+2]
				temp_tags.append([id, length, value])
				input = input[length + 2:]
			
			value_chunk = temp_tags[len(temp_tags) - 2][2]
			
			# Fail design:
			#if value_chunk == self.tags[len(self.tags)-2]:
			#	return False
			
			#if DEBUG:
			#	print "Value_chuck: " + binascii.hexlify(value_chunk)
			output = output + value_chunk
			
			return output
			
		def tagGrabber(self, id):
			"""
			
			return the whole tag from an array of tags by its tag id
			
			"""
			for entry in self.tags:
				if (entry[0] == id):
					return entry
	class DataQOS:
		"""
		
		Template to hold a example Data packet type, currently we only support simple LLC
		packets for injection, encrypted data needs to be included.
		
		"""
		injectable = 0
		
		# 802.11
		type = ""
		frame_control = ""
		duration = ""
		BSSID = ""
		SA = ""
		DA = ""
		sequence_num = ""
		QOS = ""
		crypto = ""
		
		# LLC
		
		
		def __init__(self, packet):
			# For a speed up we could use the struct.unpack() method
			# self.type, self.frame_control, struct.unpack("", packet)
			self.type = packet[0:1]
			self.frame_control = packet[1:2]
			self.duration = packet[2:4]
			self.BSSID = packet[4:10]
			self.SA = packet[10:16]
			self.DA = packet[16:22]
			self.sequence_num = packet[22:24]
			self.QOS = packet[24:26]
			self.databody = packet[26:]
			
			# TODO: dynamic lengths of injectable data. randomly?
			# Temp size is 40 bytes
			self.injectable = 40
			
		def makePacket(self, inject_data):
			"""
			
			Make a QOS data packet with injected data, fields are: Sequence num and databody
			
			"""
			self.sequence_num = generate_seqnumb()

			outbound = self.type + self.frame_control + self.duration+ self.BSSID + self.SA + self.DA + self.sequence_num + self.QOS
			
			outbound = outbound + struct.pack("B", len(inject_data)) + inject_data
			
			outbound = self.resize(outbound)
			return outbound
			
		def resize(self, outpack):
			
			while(round( (len(outpack)) % MODULUS, 2) != REMAINDER):
				outpack = outpack + os.urandom(1)
			return outpack
			
		def decode(self, input):
			
			# If the packet is not 27 bytes long it does not have any data in it. return false
			if len(input) < 27:
				return False
			
			# read the databody up to the size of the byte of length
			size, = struct.unpack("B", input[26:27])
			output = input[27:size+27]
			return  output		
	class ProbeRequest:
		"""
		
		ProbeRequst packet type template, injectable fields are sequence number and SSID.
		
		"""
		injectable = 0
		tags = []
		vendors = []
		
		type = ""
		frame_control = ""
		duration = ""
		BSSID = ""
		SA = ""
		DA = ""
		sequence_num = ""
		
		def __init__(self, packet):
			# For a speed up we could use the struct.unpack() method
			# self.type, self.frame_control, struct.unpack("", packet)
			self.type = packet[0:1]
			self.frame_control = packet[1:2]
			self.duration = packet[2:4]
			self.DA = packet[4:10]
			self.SA = packet[10:16]
			self.BSSID = packet[16:22]
			self.sequence_num = packet[22:24]
			
			packet = packet[24:]
			
			while (len(packet) >= 4):
				id = packet[:1]
				length, = struct.unpack("B", packet[1:2])
				value = packet[2:length+2]
				self.tags.append([id, length, value])
				if id == "\xdd":
					self.vendors.append([value[:3]])
				packet = packet[length + 2:]
			
			# in the event there is zero vendor tags, make one up.
			if len(self.vendors) == 0:
				self.vendors.append([os.urandom(3)])
			
			# ProbeRequests get the data injected into the ssid's
			# and are resized by a vendor tag, default SSID length is 12, again 
			# possibly signatureable.
			self.injectable = 12
			
		def makePacket(self, inject_data):
			"""
			
			Creates a packet with injected encrypted data.

			Inject data into the SSID field, this should be considered for modification to a vendor field
			
			"""

			self.sequence_num = generate_seqnumb()
			
			outbound = self.type + self.frame_control + self.duration + self.DA + self.SA + self.BSSID + self.sequence_num
			outbound = outbound + "\x00" + struct.pack("<B", len(inject_data)) + inject_data 
			for i in range(1, len(self.tags)-1):
				outbound = outbound + self.tags[i][0] + struct.pack("<B", self.tags[i][1]) + self.tags[i][2]

			return self.resize(outbound)
		def resize(self, outpack):
			"""
			
			Resizes the packet with the proper mod / REMAINDER value
			Uses last vendor tag.
			
			"""
			# counter will be the size of the tag
			# using \xdd for vendor tag.
			tag = ["\xdd", 0, self.vendors[-1][0]]
			
			while( round( (len(outpack) + tag[1] + 2) % MODULUS, 2) != REMAINDER):
				tag[2] = tag[2] + os.urandom(1)
				tag[1] = len(tag[2])
			outpack = outpack + tag[0] + struct.pack("<B", tag[1]) + tag[2]
			return outpack
		
		def decode(self, input):
			"""
			
			Decodes the encrypted data out of the inputed packet
			
			"""
			
			# sequence_num
			#output = input[22:24]
			temp_tags = []
			
			input = input[24:]
			data_size = len(input)
			
			# This should protect from non-Bunny probe requests being decoded
			if data_size < 4:
				return False
			while (len(input) >= 4):
				id = input[:1]
				length, = struct.unpack("B", input[1:2])
				value = input[2:length+2]
				temp_tags.append([id, length, value])
				input = input[length + 2:]
				
			# Check the SSID tag for sanity,
			for tag, length, value in temp_tags:
				if tag == "\x00":
					if length == 0:
						return False
					else:
						return value
					break
			return False

		def tagGrabber(self, id):
			"""
			
			return the whole tag from an array of tags by its tag id
			
			"""
			for entry in self.tags:
				if (entry[0] == id):
					return entry
					
