import sys
import string
import time
import socket
import struct
import binascii
import os
from common import *

class Unpacker:

	def __init__(self):
		self._unpackers = []
		self._isOpen = True

	def __str__(self): 
		return "Default unpacker"

	def _packetInfo(self, packet):
		s = []
		for key, value in packet[packet['top']].iteritems():
			s += ["{0} {1}".format(key, value)]
		return "#{0} {1} {2}".format(packet['raw']['seq'], packet['path'], ', '.join(s))

	def addUnpacker(self, unpacker):
		self._unpackers += [unpacker]

	def validate(self, packet):
		return True

	def process(self, packet):
		pass

	def getPayload(self, packet):
		return packet

	def relay(self, packet):
		if len(self._unpackers)>0:
			for unpacker in self._unpackers:
#				try:
#					print "Testing packet #{0} from {1} to {2}".format(packet['raw']['seq'], self, unpacker)
					if unpacker.validate(packet):
#						print "#{0} tested ok for {1}".format(packet['raw']['seq'], unpacker)
						unpacker.addPacket(packet)
						break
#					else:
#						print "#{0} tested FAILED for {1}".format(packet['raw']['seq'], unpacker)
#				except Exception as ex:
#					print "{0} error, packet #{1}: {2}".format(unpacker, packet['raw']['seq'], ex)
#			print "\n"
		else:
			# it's a leaf (no child unpackers). in this case it outputs packet information
			Log.write(self._packetInfo(packet), 3)
			
	def addPacket(self, packet):
		self.process(packet)
		self.relay(packet);

	def close(self):
		if self._isOpen:
			for unpacker in self._unpackers:
				unpacker.close()		
			self._isOpen = False

