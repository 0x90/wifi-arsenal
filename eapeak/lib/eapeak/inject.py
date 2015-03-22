"""
	-*- coding: utf-8 -*-
	inject.py
	Provided by Package: eapeak
	
	Author: Spencer McIntyre <smcintyre [at] securestate [dot] com>
	
	Copyright 2011 SecureState
	
	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
	MA 02110-1301, USA.

"""

__version__ = '0.0.5'

from binascii import hexlify, unhexlify
from socket import error as socketError
from struct import pack, unpack
from random import randint
from time import sleep
import threading
import Queue

from eapeak.common import getBSSID, getSource, getDestination
from eapeak.networks import WirelessNetwork
from eapeak.clients import WirelessClient
from eapeak.parse import UNKNOWN_SSID_NAME, parseRSNData, buildRSNData
from ipfunc import getHwAddr

from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq, Dot11Disas, Dot11QoS, Dot11ProbeResp
from scapy.layers.l2 import LLC, SNAP, EAPOL, EAP, LEAP, PEAP

RESPONSE_TIMEOUT = 1.5	# time to wait for a response
PRIVACY_NONE = 0
PRIVACY_WEP = 1
PRIVACY_WPA = 2

GOOD = '\033[1;32m[+]\033[1;m '
STATUS = '\033[1;34m[*]\033[1;m '
ERROR = '\033[1;31m[-]\033[1;m '

class SSIDBroadcaster(threading.Thread):
	"""
	This object is a thread-friendly SSID broadcaster
	It's meant to be controlled by the Wireless State Machine
	"""
	def __init__(self, interface, essid, bssid = None):
		threading.Thread.__init__(self)
		self.interface = interface
		self.essid = essid
		if not bssid:
			bssid = getHwAddr(interface)
		self.bssid = bssid.lower()
		self.broadcast_interval = 0.15
		self.channel = "\x06"
		self.setPrivacy(PRIVACY_NONE)
		self.sequence = randint(1200, 2000)
		self.__shutdown__ = False

	def __unfuckupSC__(self, fragment = 0):
		"""
		This is a reserved method to return the sequence number in a way
		that is not fucked up by a bug in how the SC field is packed in
		Scapy.
		"""
		if self.sequence >= 0xFFF:
			self.sequence = 1
		else:
			self.sequence += 1
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4) # bit shifts FTW!
		return unpack('<H', pack('>H', SC))[0]
		
	def run(self):
		"""
		This is the thread routine that broadcasts the SSID.
		"""
		while not self.__shutdown__:
			self.beacon.getlayer(Dot11).SC = self.__unfuckupSC__()
			sendp(self.beacon, iface=self.interface, verbose=False)
			sleep(self.broadcast_interval)
			
	def setPrivacy(self, value):
		"""
		Configure the privacy settings for None, WEP, and WPA
		"""
		if value == PRIVACY_NONE:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=self.essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WEP:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=self.essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WPA:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=self.essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")

	def sendBeacon(self):
		"""
		Convenience function for sending beacons without starting a thread
		"""
		self.beacon.getlayer(Dot11).SC = self.__unfuckupSC__()
		sendp(self.beacon, iface=self.interface, verbose=False)
	
	@staticmethod
	def sendBeaconEx(essid, interface, privacy = PRIVACY_NONE, bssid = None, channel = 6):
		"""
		Convenience function for sending beacons without a thread or creating an instance
		"""
		if not bssid:
			bssid = getHwAddr(interface)
		channel = chr(channel)
		sequence = randint(1200, 2000)
		
		if privacy in [PRIVACY_NONE, 'none', 'NONE']:
			beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif privacy in [PRIVACY_WEP, 'wep', 'WEP']:
			beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif privacy in [PRIVACY_WPA, 'wpa', 'WPA']:
			beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")
		else:
			raise Exception('Invalid privacy setting')
		sendp(beacon, iface=interface, verbose=False)
		
class ClientListener(threading.Thread):
	"""
	This object is a thread-friendly listener for Client connection
	attempts.
	
	The backlog corresponds to the size of the queue, if the queu is
	full because the items are not being handled fast enough then new
	association requests will be dropped and lost.
	"""
	def __init__(self, interface, backlog, essid = None, bssid = None):
		threading.Thread.__init__(self)
		self.interface = interface
		self.backlog = backlog
		self.essid = essid
		if not bssid:
			bssid = getHwAddr(interface)
		self.bssid = bssid.lower()
		self.lastpacket = None
		self.client_queue = Queue.Queue(self.backlog)	# FIFO
		self.channel = "\x06"
		self.sequence = randint(1200, 2000)
		self.__shutdown__ = False
		
	def __unfuckupSC__(self, fragment = 0):
		"""
		This is a reserved method to return the sequence number in a way
		that is not fucked up by a bug in how the SC field is packed in
		Scapy.
		"""
		if self.sequence >= 0xFFF:
			self.sequence = 1
		else:
			self.sequence += 1
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4) # bit shifts FTW!
		return unpack('<H', pack('>H', SC))[0]
		
	def __stopfilter__(self, packet):
		"""
		This is the stop filter for Scapy to be used to check if the
		packet was sent to EAPeak.
		"""
		if (packet.haslayer('Dot11Auth') or packet.haslayer('Dot11AssoReq')):
			if getBSSID(packet) == self.bssid and getSource(packet) != self.bssid:
				self.lastpacket = packet
				return True
			return False
		elif packet.haslayer('Dot11ProbeReq'):
			self.lastpacket = packet
			return True
		return False
			
	def setPrivacy(self, value):
		"""
		Configure the privacy settings for None, WEP, and WPA
		"""
		if value == PRIVACY_NONE:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info='')/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WEP:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID",info='')/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WPA:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info='')/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")
		
	def run(self):
		"""
		This is the thread routine that handles probe requests and sends
		probe responses when appropriate.
		"""
		while not self.__shutdown__:
			sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
			if self.lastpacket:
				if self.lastpacket.haslayer('Dot11ProbeReq'):
					ssid = None											# not to be confused with self.essid, they could be different and need to be evaluated
					tmp = self.lastpacket.getlayer(Dot11ProbeReq)
					while tmp:
						tmp = tmp.payload
						if tmp.fields['ID'] == 0:
							ssid = tmp.info
							break
					if ssid == None:
						continue
					elif ssid == '' and self.essid:
						ssid = self.essid
					if self.essid == None or self.essid == ssid:
						self.probe_response_template.getlayer(Dot11).addr1 = getSource(self.lastpacket)
						self.probe_response_template.getlayer(Dot11Elt).info = ssid
						sendp(self.probe_response_template, iface=self.interface, verbose=False)
					self.lastpacket = None
					continue
				clientMAC = getSource(self.lastpacket)
				if not self.client_queue.full():
					self.client_queue.put(clientMAC, False)
				self.lastpacket = None
				continue

class WirelessStateMachine:
	"""
	This provides a psuedo-socket like object that provides a stack for
	Dot11 communications using Scapy.
	
	Remember:
	States Are For Smashing
	"""
	def __init__(self, interface, bssid, source_mac = None, dest_mac = None):
		"""
		You must specify a BSSID and a Local MAC address because the
		entire point of this code is to facilitate stateful connections.
		"""
		if not source_mac:
			source_mac = getHwAddr(interface)
		if not dest_mac:
			dest_mac = bssid
		self.interface = interface
		
		self.bssid = bssid.lower()
		self.source_mac = source_mac.lower()
		self.dest_mac = dest_mac.lower()
		
		self.connected = False	# connected / associated
		self.__shutdown__ = False
		self.sequence = randint(1200, 2000)
		self.lastpacket = None
		self.timeout = RESPONSE_TIMEOUT
		
	def __del__(self):
		self.shutdown()
		self.close()
	
	def __unfuckupSC__(self, fragment = 0):
		"""
		This is a reserved method to return the sequence number in a way
		that is not fucked up by a bug in how the SC field is packed in
		Scapy.
		"""
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4) # bit shifts FTW!
		return unpack('<H', pack('>H', SC))[0]
		
	def __stopfilter__(self, packet):
		"""
		This is the stop filter for Scapy to be used to check if the
		packet was sent to this WirelessStateMachine instance.
		"""
		real_destination = getDestination(packet)
		real_bssid = getBSSID(packet)
		#real_source = getSource(packet)
		if real_destination == self.source_mac and real_bssid == self.bssid:# and real_source == self.dest_mac:
			self.lastpacket = packet
			return True
		self.lastpacket = None
		return False
		
	def connect(self, essid, rsnInfo = ''):
		"""
		Connect/Associate with an access point.
		errDict = {
			-1:"Already Connected",
			0:"No Error",
			1:"Failed To Get Probe Response",
			2:"Failed To Get Authentication Response",
			3:"Failed To Get Association Response",
			4:"Authentication Request Received Fail Response",
			5:"Association Request Received Fail Response"
		}
		"""
		# Dot11 Probe Request (to get authentication information if applicable)
		if rsnInfo == None:	# None explicitly means go get it, leave it '' to proceed with out it
			rsnInfo = self.getRSNInformation(essid)
		
		# Dot11 Authentication Request
		sendp(	RadioTap()/
				Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__())/
				Dot11Auth(seqnum=1),
				iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=self.timeout, stop_filter=self.__stopfilter__)
		if self.lastpacket == None or not self.lastpacket.haslayer('Dot11Auth'):
			return 2
		if self.lastpacket.getlayer('Dot11Auth').status != 0:
			return 4
		
		# Dot11 Association Request
		sendp(	RadioTap()/
				Dot11(addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), subtype=0)/
				Dot11AssoReq(cap='ESS+short-preamble+short-slot', listen_interval=10)/
				Dot11Elt(ID=0, info=essid)/
				Dot11Elt(ID=1, info='\x82\x84\x0b\x16\x24\x30\x48\x6c')/
				Dot11Elt(ID=50, info='\x0c\x12\x18\x60')/
				rsnInfo,
				iface=self.interface, verbose=False)

		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=self.timeout, stop_filter=self.__stopfilter__)
		if self.lastpacket == None or not self.lastpacket.haslayer(Dot11AssoResp):
			return 3
		
		if self.lastpacket.getlayer(Dot11AssoResp).status != 0:
			return 5
		
		self.connected = True
		self.sequence = 0	# reset it
		return 0
		
	def close(self):
		"""
		Disassociate from the access point,  This does not veify that
		the AP received the message and should be considred a
		best-effort attempt.
		errDict = {
			-1:"Not Connected",
			0:"No Error"
		}
		"""
		if not self.connected:
			return -1
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		self.connected = False
		return 0
	
	def getRSNInformation(self, essid):
		sendp(	RadioTap()/
				Dot11(addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), subtype=4)/
				Dot11ProbeReq()/
				Dot11Elt(ID=0, info=essid)/
				Dot11Elt(ID=1, info='\x82\x84\x0b\x16\x24\x30\x48\x6c')/
				Dot11Elt(ID=50, info='\x0c\x12\x18\x60'),
				iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=self.timeout, stop_filter=self.__stopfilter__)
		if self.lastpacket == None or not self.lastpacket.haslayer('Dot11ProbeResp'):
			return None
		probeResp = self.lastpacket.getlayer(Dot11ProbeResp)
		tmp = probeResp.getlayer(Dot11Elt)
		while tmp:
			if tmp.fields.get('ID') == 48:
				rsnInfo = tmp
				break
			else:
				tmp = tmp.payload
		if rsnInfo == None:
			rsnInfo = ''	# we didn't find it in the probe response, so we'll return an empty string
		else:
			rsnInfo = parseRSNData(rsnInfo.info)
			rsnInfo = buildRSNData(rsnInfo)
			rsnInfo = '\x30' + chr(len(rsnInfo)) + rsnInfo
		return rsnInfo
	
	def recv(self, bufferlen = 0):
		"""
		Read a frame and return the information above the Dot11 layer.
		"""
		sniff(iface=self.interface, store=0, timeout=self.timeout, stop_filter=self.__stopfilter__)
		if self.lastpacket:
			return self.lastpacket
		else:
			return None
		
	def send(self, data, dot11_type = 2, dot11_subtype = 8, FCfield = 0x02, raw = True):
		"""
		Send a frame, if raw, insert the data above the Dot11QoS layer.
		"""
		frame = RadioTap()/Dot11(FCfield=FCfield, addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=dot11_type, subtype=dot11_subtype)
		if raw:
			frame = frame/data
		else:
			frame = frame/Dot11QoS()/data
		sendp(frame, iface=self.interface, verbose=False)
		self.sequence += 1
		
	def shutdown(self):
		"""
		Shutdown and disassociate from the AP.
		"""
		if self.connected:
			self.close()
		self.__shutdown__ = True

class WirelessStateMachineEAP(WirelessStateMachine):
	"""
	This is to keep the EAP functionality seperate so the core State-
	Machine can be repurposed for other projects.
	"""
	def check_eap_type(self, eaptype, outer_identity = 'user', eapol_start = False):
		"""
		Check that an eaptype is supported.
		errDict = {
			0:"supported",
			1:"not supported",
			2:"could not determine",
			3:"identity rejected"
		}
		"""
		eapid = randint(1, 254)
		if eapol_start:
			eapol_start_request = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=1)
			self.sequence += 1
			for i in range(0, 3):
				sendp(eapol_start_request, iface=self.interface, verbose=False)
				sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
				if not self.lastpacket == None:
					if self.lastpacket.haslayer('EAP'):
						fields = self.lastpacket.getlayer(EAP).fields
						if 'type' in fields and fields['type'] == 1 and fields['code'] == 1:
							i = 0
							eapid = fields['id']
							break
			if i == 2:
				return 2

		eap_identity_response = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0)/EAP(code=2, type=1, id=eapid, identity=outer_identity)
		self.sequence += 1
		eap_legacy_nak = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0, len=6)/EAP(code=2, type=3, id=eapid + 1, eap_types=[ eaptype ])
		self.sequence += 1
		
		for i in range(0, 3):
			sendp(eap_identity_response, iface=self.interface, verbose=False)
			sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
			if not self.lastpacket == None:
				if self.lastpacket.haslayer('EAP'):
					fields = self.lastpacket.getlayer(EAP).fields
					if fields['code'] == 4:	# 4 is a failure
						return 3
					if 'type' in fields and fields['type'] == eaptype:
						return 0
					i = 0
					break
		if i == 2:
			return 2
		
		for i in range(0, 3):
			sendp(eap_legacy_nak, iface=self.interface, verbose=False)
			sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
			if not self.lastpacket == None:
				if self.lastpacket.haslayer('EAP'):
					fields = self.lastpacket.getlayer(EAP).fields
					if 'type' in fields and fields['type'] == eaptype:
						return 0
					else:
						return 1
		return 2

class WirelessStateMachineSoftAP(WirelessStateMachine):
	"""
	This is a Python Soft AP object, it manages SSIDBroadcaster and
	ClientListener Threads.

	Tested Associations with:
		Windows 7 SP1
		Windows XP SP3
		iPod Touch 1.1.4
		Android 2.2
	"""
	def __init__(self, interface, bssid, essid = None):
		self.essid = essid
		self.privacy = PRIVACY_NONE
		self.backlog = 5												# sets a default incase listen() hasn't been called, which may be the case if we're responding to multiple network probes
		self.max_tries = 3
		self.asso_resp_data = Dot11AssoResp(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l')
		WirelessStateMachine.__init__(self, interface, bssid, bssid, None)
		if essid:
			self.networkDescriptor = WirelessNetwork(essid, bssid)
		else:
			self.networkDescriptor = WirelessNetwork(UNKNOWN_SSID_NAME, bssid)	# this is kind of lame
		
	def __del__(self):
		self.shutdown()
		
	def listen(self, backlog,  broadcast_interval = 0.25):
		"""
		This sets and starts the SSIDBroadcaster thread and is meant to
		be called once per initialization.
		"""
		self.backlog = backlog
		self.ssid_broadcaster = SSIDBroadcaster(self.interface, self.essid, self.bssid)
		self.ssid_broadcaster.broadcast_interval = broadcast_interval
		self.ssid_broadcaster.setPrivacy(self.privacy)
		self.ssid_broadcaster.start()
			
	def accept(self):
		"""
		This is called after the listen() call and sets up the
		ClientListener, which will respond to probe requests.
		This method can (and often will be) called multiple times.  It
		returns a new WirelessStateMachine instance, pre-configured for
		communication with the client machine.  The client will already
		be associated with the PythonSoftAP.  The WirelessStateMachine
		instance that is returned also contains an attribute of
		"clientDescriptor" which contains a WirelessClient instance that
		describes it.
		
		The Dot11 Authentication frames and Dot11 Association frames are
		transfered in this call, implying the main calling thread is
		blocking.  It is possible that the ClientListener thread may
		queue multiple clients that are attempting to associate with the
		PythonSoftAP but may be lost if accept() is not called again
		before the clients timeout.
		"""
		if self.__shutdown__: return
		if not hasattr(self, 'client_listener'):
			self.client_listener = ClientListener(self.interface, self.backlog, self.essid, self.bssid)
			self.client_listener.setPrivacy(self.privacy)
			self.client_listener.start()
		while not self.__shutdown__:
			if self.client_listener.client_queue.empty():
				continue
			clientMAC = self.client_listener.client_queue.get(True, 1)
			sockObj = WirelessStateMachine(self.interface, self.bssid, self.source_mac, clientMAC)
			sockObj.clientDescriptor = WirelessClient(self.bssid, clientMAC)
			
			tries = self.max_tries
			sockObj.send(Dot11Auth(seqnum=2), 0, 11, 0, True)
			while tries:
				tries -= 1
				data = sockObj.recv()
				if not data: continue
				if data.haslayer('Dot11AssoReq'): 
					break
				elif data.haslayer(Dot11Auth):
					sockObj.send(Dot11Auth(seqnum=2), 0, 11, 0, True)
			sockObj.send(self.asso_resp_data, 0, 1, 0x10, True)
		
			return sockObj, clientMAC

	def shutdown(self):
		"""
		Shutdown and join the SSIDBroadcaster and ClientListener
		threads.
		"""
		if hasattr(self, 'client_listener'):
			self.client_listener.__shutdown__ = True
			self.client_listener.join()
		if hasattr(self, 'ssid_broadcaster'):
			self.ssid_broadcaster.__shutdown__ = True
			self.ssid_broadcaster.join()
		WirelessStateMachine.shutdown(self)
			
class WirelessStateMachineSoftAPEAP(WirelessStateMachineSoftAP):
	def __init__(self, interface, bssid, essid):
		"""
		EAP version requires an ESSID to target, and automatically
		sets the privacy to WPA.
		"""
		WirelessStateMachineSoftAP.__init__(self, interface, bssid, essid)
		self.privacy = PRIVACY_WPA
		
		# EAP Crap Goes Here
		self.__mschap_challenge__ = None
		self.eap_priorities = [ ]
		self.eap_handlers = {
								17:self.handleLEAP,
								25:self.handlePEAP
							}
	
	@property
	def mschap_challenge(self):
		if self.__mschap_challenge__ == None:
			return ''.join([ pack('B', randint(0, 255)) for x in range(8) ])
		return self.__mschap_challenge__
	
	@mschap_challenge.setter
	def mschap_challenge(self, value):
		if value == None:
			self.__mschap_challenge__ = None
			return
		elif len(value) != 8:
			raise ValueError('Invalid Challenge Length')
		self.__mschap_challenge__ = value
	
	@mschap_challenge.deleter
	def mschap_challenge(self):
		del self.__mschap_challenge__
	
	def addEapType(self, eaptype):
		if not eaptype in self.eap_handlers.keys():
			return False
		if eaptype in self.eap_priorities:
			return True
		self.eap_priorities.append(eaptype)
		return True

	def accept(self):
		"""
		This extends the WirelessStateMachineSoftAP accept() method but
		adds in the exchange of EAP identities.
		"""
		while not self.__shutdown__:
			(sockObj, clientMAC) = WirelessStateMachineSoftAP.accept(self)
			tries = self.max_tries
			while tries:
				tries -= 1
				data = sockObj.recv()
				if not data: continue
				if data.haslayer(EAPOL):
					tries = self.max_tries
					break
				elif data.haslayer('Dot11AssoReq'):
					sockObj.send(self.asso_resp_data, 0, 1, 0x10, True)
			if tries != self.max_tries:
				continue												# shit failed in that loop up there
			
			sockObj.sequence = 1
			while tries:
				tries -= 1
				sockObj.send('\x00\x00'/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=2, type=0)/EAP(code=1, type=1, id=0, identity='\x00networkid=' + self.essid + ',nasid=AP,portid=0'), FCfield=2, raw=True)
				data = sockObj.recv()
				if data == None:
					continue
				if not data.haslayer(EAP):
					continue
				data = data.getlayer(EAP)
				if not 'identity' in data.fields:
					continue
				tries = self.max_tries
				break
			if tries != self.max_tries:
				continue

			eaptype = self.eap_priorities[0]
			(errCode, eap_types) = self.eap_handlers[eaptype](sockObj, data.identity)
			
			self.networkDescriptor.addClient(sockObj.clientDescriptor)
			return sockObj, clientMAC
			
	def handleLEAP(self, sockObj, identity):
		self.networkDescriptor.addEapType(17)
		tries = self.max_tries
		while tries:
			tries -= 1
			sockObj.send('\x00\x00'/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=2, type=0)/EAP(code=1, type=17, id=2)/LEAP(data=self.mschap_challenge), FCfield=2, raw=True)
			data = sockObj.recv()
			if data == None:
				continue
			if not data.haslayer(EAP):
				continue
			if not data.haslayer(LEAP):
				eap = data.getlayer(EAP)
				if eap.type == 3:
					return 1, tuple(eap.eap_types)
				continue
			leap = data.getlayer(LEAP)
			sockObj.clientDescriptor.addIdentity(17, identity)
			sockObj.clientDescriptor.addEapType(17)
			sockObj.clientDescriptor.addMSChapInfo(17, self.mschap_challenge, leap.data, identity)
			return 0, None 
		if tries != self.max_tries:
			return 2, None

	def handlePEAP(self, sockObj, identity):
		"""
		This is not yet supported.  Don't even bother trying.
		"""
		self.networkDescriptor.addEapType(25)
		tries = self.max_tries
		while tries:
			tries -= 1
			sockObj.send('\x00\x00'/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=2, type=0)/EAP(code=1, type=25, id=2)/PEAP(version=1, flags='start'), FCfield=2, raw=True)
			return 0, None
		if tries != self.max_tries:
			return 2, None
