#!/usr/bin/env python
import socket 
import time
import struct


def createPacketSink(interface="mon0"):
	rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	rawSocket.bind((interface, 0x0003))
	return rawSocket

def parseRadioTapHeader(data):
	version = struct.unpack('B', data[0])[0]
	#data[1] is unused
	length = struct.unpack('H', data[2:4])[0]
	fieldsPresent = struct.unpack('I', data[4:8])[0]#its a bitset
	return version, length, fieldsPresent, data[length:]


#Frame types		: 0 = management, 1 = control, 2 = data, 3 = reserved.
#Subframe types		: 0 = association req/data, 1 = assoc resp, 4 = probe req, 5 = probe resp, 8 = beacon, 10 = Dissociation, 11 = Authentication
#			: 12 = Deauthentication
#http://ilovewifi.blogspot.com.au/2012/07/80211-frame-types.html
#http://www.wildpackets.com/images/compendium/802dot11_frame.gif
class WifiFrame(object):
	def __init__(self, data, deepdecode=False):
		self.version		= ord(data[0]) & 0b00000011
		self.type		= (ord(data[0]) >> 2) & 0b00000011
		self.subtype		= (ord(data[0]) >> 4) & 0b00001111
		self.toDS		= bool(ord(data[1]) & 1)
		self.fromDS		= bool((ord(data[1]) >> 1) & 1)
		self.moreFrag		= bool((ord(data[1]) >> 2) & 1)
		self.retry		= bool((ord(data[1]) >> 3) & 1)
		self.durationID		= data[2:4]
		self.dest		= data[4:10]
		self.src		= data[10:16] #FIXME: Not present for control frames
		self.addr3		= data[16:24] #FIXME: Not present for control frames
		self.seqControl		= data[24:26] #FIXME: Not present for control frames
		self.addr4		= data[26:32] #FIXME: Not always present depending on type
		self.data		= data[36:]
		self.tags		= []#management frame information elements - only used on mngmt frames obviously
		#skipping pwr mngment, more data, wep, order

		if deepdecode:
			self.deepDecode()

	def deepDecode(self):
		if self.type == 0:
			try:
				self._decodeMngmt()
			except Exception, e:
				print "Exception decoding management frame: " + str(e)


	def ssid(self):
		"""Only call this after deepDecode() has been invoked."""
		if self.isBeacon() or self.isProbeResp() or self.isProbeReq():
			for tag in self.tags:
				if tag[0] == 0:#0 is the type for an SSID
					return str(tag[1])

	def _decodeMngmt(self):
		"""Called internally to decode the data section of management frames."""
		i = 0
		while i < len(self.data):
			tpe = ord(self.data[i])
			data = self.data[i+2:i+2+ord(self.data[i+1])]
			i += 2+length
			self.tags.append((tpe,data))
			
	def isBeacon(self):
		return (self.subtype == 8) and (self.type == 0)

	def isProbeReq(self):
		return (self.subtype == 4) and (self.type == 0)
		
	def isProbeResp(self):
		return (self.subtype == 5) and (self.type == 0)
		

	def display(self):
		print ""
		if self.isBeacon():
			print "Beacon SSID: ", self.ssid()
		elif self.isProbeReq():
			print "Probe Request SSID: ", self.ssid()
		elif self.isProbeResp():
			print "Probe Response SSID: ", self.ssid()
		else:
			print "Type: ", self.type
			print "Subtype: ", self.subtype

		print "Source: ", self.src.encode('hex')
		print "Destination: ", self.dest.encode('hex')



if __name__ == "__main__":
	rawSocket = createPacketSink()
	while True:
		pkt = rawSocket.recvfrom(2548)[0] #each recv from call gets a most one packet
		version, length, fields, frame = parseRadioTapHeader(pkt)
		obj = WifiFrame(frame, True)
		#if obj.isBeacon():
		if not obj.isBeacon():
			obj.display()

