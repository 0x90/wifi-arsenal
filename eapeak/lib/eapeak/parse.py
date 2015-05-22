"""
	-*- coding: utf-8 -*-
	parse.py
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

# TODO: remove clients with an eap identity of eapscan because they're probably us.

__version__ = '0.1.5'

import os
import sys
import signal
try:
	import curses
	CURSES_CAPABLE = True
except ImportError:
	CURSES_CAPABLE = False
from struct import pack, unpack
from binascii import unhexlify
from time import sleep
from xml.dom import minidom
from datetime import datetime
from xml.etree import ElementTree
from base64 import standard_b64decode as b64decode
from M2Crypto import X509

from scapy.utils import PcapReader
from scapy.layers.l2 import eap_types as EAP_TYPES
import scapy.packet
import scapy.layers.all
from scapy.sendrecv import sniff

from eapeak.common import getBSSID, getSource, getDestination, EXPANDED_EAP_VENDOR_IDS
import eapeak.networks 
import eapeak.clients

# Statics
UNKNOWN_SSID_NAME = 'UNKNOWN_SSID'
XML_FILE_NAME = 'eapeak.xml'
SSID_SEARCH_RECURSION = 5
CURSES_LINE_BREAK = (0, '')
CURSES_REFRESH_FREQUENCY = 0.10
CURSES_LOWER_REFRESH_FREQUENCY = 5	# frequency of CURSES_REFRESH_FREQUENCY, also used for calls to exportXML
CURSES_MIN_X = 99					# minimum screen size
CURSES_MIN_Y = 25
TAB_LENGTH = 4						# in spaces
TAB_DEPTH_2 = 2 * TAB_LENGTH
TAB_DEPTH_3 = 3 * TAB_LENGTH
TAB_DEPTH_4 = 4 * TAB_LENGTH

USER_MARKER = '=> '
USER_MARKER_OFFSET = 8
SSID_MAX_LENGTH = 32
from scapy.layers.l2 import eap_types as EAP_TYPES
from scapy.layers.l2 import EAP, EAP_TLS, LEAP, EAP_TTLS, PEAP, EAP_Fast, EAP_Expanded
from scapy.layers.ssl import TLSv1RecordLayer, TLSv1ClientHello, TLSv1ServerHello, TLSv1ServerHelloDone, TLSv1KeyExchange, TLSv1Certificate
EAP_TYPES[0] = 'NONE'
	
def mergeWirelessNetworks(source, destination):
	"""
	Merge information about two wireless networks, used to preserve
	information when one is un-orphaned.
	"""
	for bssid in source.bssids:
		destination.addBSSID(bssid)
	
	for mac, clientobj in source.clients.items():
		destination.addClient(clientobj)
		
	for eaptype in source.eapTypes:
		destination.addEapType(eaptype)
		
	for cert in source.x509certs:
		destination.addCertificate(cert)
	return destination

class wpsDataHolder(dict):
	"""
	This wraps a dictionary and a few key methods to allow types to be
	retreived from either their numerical cylon value or thier alphabetical
	human value
	
	Keys are not case sensitive because I like it that way.
	"""
	__h_to_c__ = {
		'authentication type flags':0x1004,
		'authenticator':0x1005,
		'configuration error':0x1009,
		'encryption type flags':0x1010,
		'device name':0x1011, 
		'encrypted settings':0x1018,
		'enrollee nonce':0x101a,
		'manufacturer':0x1021,
		'message type':0x1022,
		'model name':0x1023,
		'model number':0x1024,
		'os version':0x102d,
		'registrar nonce':0x1039,
		'uuid':0x1048,
		'version':0x104a,
	}
	
	def __getitem__(self, index):
		if isinstance(index, str):
			if index.lower() in self.__h_to_c__:
				index = self.__h_to_c__[index.lower()]
			else:
				raise KeyError(index)
		return dict.__getitem__(self, index)

	def __setitem__(self, name, value):
		if isinstance(name, str):
			if name.lower() in self.__h_to_c__:
				name = self.__h_to_c__[name.lower()]
			else:
				raise KeyError(name)
		return dict.__setitem__(self, name, value)
	
	def get(self, item):
		if isinstance(item, str):
			if item.lower() in self.__h_to_c__:
				item = self.__h_to_c__[item.lower()]
			else:
				return None
		return dict.get(self, item)

	def has_key(self, item):
		if isinstance(item, str):
			if item.lower() in self.__h_to_c__:
				item = self.__h_to_c__[item.lower()]
			else:
				return False
		return dict.has_key(self, item)
	
	def keys(self):
		keys = dict.keys(self)
		new_keys = []
		for key, value in self.__h_to_c__.items():
			if value in keys:
				new_keys.append(key)
		keys.extend(new_keys)
		return keys

def parseWPSData(wpsdata, trimStrings = True):
	"""
	Take raw WPS data string and return a dictionary of types and values
	"""
	data = wpsDataHolder()
	while wpsdata:
		if len(wpsdata) < 4:
			raise Exception('invalid/corrupted WPS data')
		type = unpack('>H', wpsdata[:2])[0]
		length = unpack('>H', wpsdata[2:4])[0]
		if len(wpsdata) < (length + 4):
			raise Exception('invalid/corrupted WPS data')
		value = wpsdata[4:(4 + length)]
		wpsdata = wpsdata[(4 + length):]
		if trimStrings and type in [0x1011, 0x1021, 0x1023, 0x1024]:
			value = value.replace('\x00', '')
			if not len(value):
				continue
		data[type] = value
	return data

def parseRSNData(rsndata):
	"""
	Take raw RSN data and return a dictionary representing it's values
	Tag Number and Tag length are removed
	"""
	rsn = {}
	rsn['version'] = unpack('<H', rsndata[:2])[0]
	rsn['grp_cipher'] = rsndata[2:6]
	
	pair_ciphers = []
	nbr_pair_cipher = unpack('<H', rsndata[6:8])[0]
	rsndata = rsndata[8:]
	while nbr_pair_cipher and len(rsndata):
		pair_ciphers.append(rsndata[:4])
		rsndata = rsndata[4:]
		nbr_pair_cipher -= 1
	rsn['pair_ciphers'] = pair_ciphers
	
	auth_key_mgmt = []
	nbr_auth_key_mgmt = unpack('<H', rsndata[:2])[0]
	rsndata = rsndata[2:]
	while nbr_auth_key_mgmt and len(rsndata):
		auth_key_mgmt.append(rsndata[:4])
		rsndata = rsndata[4:]
		nbr_auth_key_mgmt -= 1
	rsn['auth_key_mgmts'] = auth_key_mgmt
	rsn['capabilities'] = rsndata
	return rsn

def buildRSNData(rsn):
	version = rsn.get('version') or 1
	rsndata = pack('<H', version)
	rsndata += rsn['grp_cipher']
	rsndata += pack('<H', 1)
	rsndata += rsn['pair_ciphers'][0]
	rsndata += pack('<H', 1)
	rsndata += rsn['auth_key_mgmts'][0]
	rsndata += rsn.get('capabilities') or '\x00\x00'
	return rsndata
	
class EapeakParsingEngine:
	"""
	This is the main parsing engine that manages all of the networks.
	
	Notable attributes:
	KnownNetworks: holds wireless network objects, indexed by SSID if available, BSSID if orphaned
	BSSIDToSSIDMap: holds SSIDs, indexed by BSSIDS, so you can obtain network objects by BSSID
	OrphanedBSSIDs: holds BSSIDs that are not associated with a known SSID
	fragment_buffer: holds buffers (lists), indexed by connection strings (src_mac + ' ' + dst_mac)
	"""
	def __init__(self, targetSSIDs = [ ]):
		self.KnownNetworks = { }							# holds wireless network objects, indexed by SSID if available, BSSID if orphaned
		self.BSSIDToSSIDMap = { }							# holds SSIDs, indexed by BSSIDS, so you can obtain network objects by BSSID
		self.OrphanedBSSIDs = [ ]							# holds BSSIDs that are not associated with a known SSID
		self.packets = [ ]
		self.targetSSIDs = targetSSIDs
		self.packetCounter = 0
		self.fragment_buffer = { }							# holds buffers (lists), indexed by connection strings (src_mac + ' ' + dst_mac)
		
	def parseLiveCapture(self, packet, quite = True):
		"""
		Function is meant to be passed to Scapy's sniff() function similar to:
		lambda packet: eapeakParser.parseLiveCapture(packet, use_curses)
		
		sniff(iface = 'mon0', prn = lambda packet: eapeakParser.parseLiveCapture(packet, False) )
		"""
		self.parseWirelessPacket(packet)
		if quite:
			return
		sys.stdout.write('Packets: ' + str(self.packetCounter) + ' Wireless Networks: ' + str(len(self.KnownNetworks)) + '\r')
		sys.stdout.flush()
		
	def parsePCapFiles(self, pcapFiles, quite = True):
		"""
		Take one more more (list, or tuple) of pcap files and parse them
		into the engine.
		"""
		if not hasattr(pcapFiles, '__iter__'):
			if isinstance(pcapFiles, str):
				pcapFiles = [ pcapFiles ]
			else:
				return
		for i in range(0, len(pcapFiles)):
			pcap = pcapFiles[i]
			pcapName = os.path.split(pcap)[1]
			if not quite:
				sys.stdout.write("Reading PCap File: {0}\r".format(pcapName))
				sys.stdout.flush()
			if not os.path.isfile(pcap):
				if not quite:
					sys.stdout.write("Skipping File {0}: File Not Found\n".format(pcap))
					sys.stdout.flush()
				continue
			elif not os.access(pcap, os.R_OK):
				if not quite:
					sys.stdout.write("Skipping File {0}: Permissions Issue\n".format(pcap))
					sys.stdout.flush()
				continue
			pcapr = PcapReader(pcap)
			packet = pcapr.read_packet()
			i = 1
			try:
				while packet != None:
					if not quite:
						sys.stdout.write('Parsing File: ' + pcap + ' Packets Done: ' + str(i) + '\r')
						sys.stdout.flush()
					self.parseWirelessPacket(packet)
					packet = pcapr.read_packet()
					i += 1
				i -= 1
				if not quite:
					sys.stdout.write((' ' * len('Parsing File: ' + pcap + ' Packets Done: ' + str(i))) + '\r')
					sys.stdout.write('Done With File: ' + pcap + ' Read ' + str(i) + ' Packets\n')
					sys.stdout.flush()
			except KeyboardInterrupt:
				if not quite:
					sys.stdout.write("Skipping File {0} Due To Ctl+C\n".format(pcap))
					sys.stdout.flush()
			except:
				if not quite:
					sys.stdout.write("Skipping File {0} Due To Scapy Exception\n".format(pcap))
					sys.stdout.flush()
			self.fragment_buffer = {}
			pcapr.close()
			
	def parseXMLFiles(self, xmlFiles, quite = True):
		"""
		Load EAPeak/Kismet style XML files for information.  This is
		faster than parsing large PCap files.
		"""
		if not hasattr(xmlFiles, '__iter__'):
			if isinstance(xmlFiles, str):
				xmlFiles = [ xmlFiles ]
			else:
				return
		for xmlfile in xmlFiles:
			if not os.path.isfile(xmlfile):
				if not quite:
					sys.stdout.write("Skipping File {0}: File Not Found\n".format(xmlfile))
					sys.stdout.flush()
				continue
			elif not os.access(xmlfile, os.R_OK):
				if not quite:
					sys.stdout.write("Skipping File {0}: Permissions Issue\n".format(xmlfile))
					sys.stdout.flush()
				continue
			sys.stdout.write("Parsing XML  File: {0}".format(xmlfile))
			sys.stdout.flush()
			e = ElementTree.parse(xmlfile)
			for network in e.findall('wireless-network'):
				ssid = network.find('SSID')
				if not ElementTree.iselement(ssid) or not ElementTree.iselement(ssid.find('type')):
					continue
				elif ssid.find('type').text.strip() != 'Beacon':
					continue
				ssid = ssid.find('essid')
				if ElementTree.iselement(ssid):
					if ssid.text == None:
						ssid = UNKNOWN_SSID_NAME
					else:
						ssid = ssid.text.strip()
					newNetwork = eapeak.networks.WirelessNetwork(ssid)
				else:
					continue
				for bssid in network.findall('BSSID'):
					bssid = bssid.text.strip()
					newNetwork.addBSSID(bssid)
					if ssid != UNKNOWN_SSID_NAME:
						self.BSSIDToSSIDMap[bssid] = ssid
					else:
						self.BSSIDToSSIDMap[bssid] = bssid
						self.OrphanedBSSIDs.append(bssid)
				eaptypes = network.find('SSID').find('eap-types')
				if ElementTree.iselement(eaptypes):
					for eaptype in eaptypes.text.strip().split(','):
						if eaptype.isdigit():
							newNetwork.addEapType(int(eaptype))
				expandedVendorIDs = network.find('SSID').find('expanded-vendor-ids')
				if ElementTree.iselement(expandedVendorIDs):
					for vendorid in expandedVendorIDs.text.strip().split(','):
						if vendorid.isdigit():
							newNetwork.addExpandedVendorID(int(vendorid))
				wpsXMLData = network.find('wps-data')
				if ElementTree.iselement(wpsXMLData):
					wpsData = wpsDataHolder()
					for elem in wpsXMLData:
						key = elem.tag.replace('-', ' ')
						value = elem.text.strip()
						encoding = elem.get('encoding')
						if encoding == 'hex':
							wpsData[key] = unhexlify(value)
						elif encoding == 'base64':
							wpsData[key] = b64decode(value)
						else:
							wpsData[key] = value
					if len(wpsData):
						newNetwork.wpsData = wpsData
							
				for client in network.findall('wireless-client'):
					bssid = client.find('client-bssid')
					if ElementTree.iselement(bssid):
						bssid = bssid.text.strip()
					else:
						continue
					client_mac = client.find('client-mac').text.strip()
					newClient = eapeak.clients.WirelessClient(bssid, client_mac)
					eaptypes = client.find('eap-types')
					if ElementTree.iselement(eaptypes):
						eaptypes = eaptypes.text
						if eaptypes != None:
							for eaptype in eaptypes.strip().split(','):
								if eaptype.isdigit():
									newClient.addEapType(int(eaptype))
					identities = client.findall('identity') or []
					for identity in identities:
						tmp = identity.get('eap-type')
						if tmp.isdigit():
							newClient.addIdentity(int(tmp), identity.text.strip())
					mschaps = client.findall('mschap') or []
					for mschap in mschaps:
						newClient.addMSChapInfo(
							int(mschap.get('eap-type')),
							unhexlify(mschap.find('challenge').text.strip().replace(':', '')),
							unhexlify(mschap.find('response').text.strip().replace(':', '')),
							mschap.get('identity')
						)
					wpsXMLData = client.find('wps-data')
					if ElementTree.iselement(wpsXMLData):
						wpsData = wpsDataHolder()
						for elem in wpsXMLData:
							key = elem.tag.replace('-', ' ')
							value = elem.text.strip()
							encoding = elem.get('encoding')
							if encoding == 'hex':
								wpsData[key] = unhexlify(value)
							elif encoding == 'base64':
								wpsData[key] = b64decode(value)
							else:
								wpsData[key] = value
						if len(wpsData):
							newClient.wpsData = wpsData
					newNetwork.addClient(newClient)
				for cert in network.findall('certificate'):
					if cert.get('encoding') == 'DER':
						newNetwork.addCertificate(X509.load_cert_string(b64decode(cert.text.strip()), X509.FORMAT_DER))
					elif cert.get('encoding') == 'PEM':
						newNetwork.addCertificate(X509.load_cert_string(b64decode(cert.text.strip()), X509.FORMAT_PEM))
				if ssid != UNKNOWN_SSID_NAME:
					self.KnownNetworks[ssid] = newNetwork
				else:
					self.KnownNetworks[bssid] = newNetwork
				"""
				if ssid == UNKNOWN_SSID_NAME and len(network.findall('BSSID')) > 1:
					there will be an issue with where to store the single network object.
					If there is a client and the network is added to KnownNetworks each time this occurs then the client will appear to under each network but only
					be associated with the single BSSID.  This problem needs to be addressed and throughly tested.
				"""
			sys.stdout.write(" Done\n")
			sys.stdout.flush()
	
	def exportXML(self, filename = XML_FILE_NAME):
		"""
		Exports an XML file that can be reimported with the parseXMLFiles
		function.
		"""
		eapeakXML = ElementTree.Element('detection-run')
		eapeakXML.set('eapeak-version', __version__)
		eapeakXML.append(ElementTree.Comment(' Summary: Found ' + str(len(self.KnownNetworks)) + ' Network(s) '))
		eapeakXML.append(ElementTree.Comment(datetime.now().strftime(' Created %A %m/%d/%Y %H:%M:%S ')))
		networks = self.KnownNetworks.keys()
		if not networks:
			return
		networks.sort()
		for network in networks:
			eapeakXML.append(self.KnownNetworks[network].getXML())
		xmldata = minidom.parseString(ElementTree.tostring( eapeakXML )).toprettyxml()
		if xmldata:
			tmpfile = open(filename, 'w')
			tmpfile.write(xmldata)
			tmpfile.close()
						
	def parseWirelessPacket(self, packet):
		"""
		This is the core packet parsing routine.  It takes a Scapy style
		packet object as an argument.
		"""
		if packet.name == 'RadioTap dummy':
			packet = packet.payload										# offset it so we start with the Dot11 header
		shouldStop = False
		self.packetCounter += 1
		# this section finds SSIDs in Bacons, I don't like this section, but I do like bacon
		if packet.haslayer('Dot11Beacon') or packet.haslayer('Dot11ProbeResp') or packet.haslayer('Dot11AssoReq'):
			tmp = packet
			for x in range(0, SSID_SEARCH_RECURSION):
				if 'ID' in tmp.fields and tmp.fields['ID'] == 0 and 'info' in tmp.fields:	# this line verifies that we found an SSID
					if tmp.fields['info'] == '\x00':
						break	# null SSIDs are useless
					if self.targetSSIDs and tmp.fields['info'] not in self.targetSSIDs:	# Obi says: These are not the SSIDs you are looking for...
						break
					bssid = getBSSID(packet)
					if not bssid:
						return
					ssid = ''.join([c for c in tmp.fields['info'] if ((ord(c) > 31 or ord(c) == 9) and ord(c) < 128)])
					if not ssid:
						return
					if bssid in self.OrphanedBSSIDs:								# if this info is relating to a BSSID that was previously considered to be orphaned
						newNetwork = self.KnownNetworks[bssid]						# retrieve the old one
						del self.KnownNetworks[bssid]								# delete the old network's orphaned reference
						self.OrphanedBSSIDs.remove(bssid)
						self.BSSIDToSSIDMap[bssid] = ssid							# this changes the map from BSSID -> BSSID (for orphans) to BSSID -> SSID
						newNetwork.updateSSID(ssid)
						if ssid in self.KnownNetworks:
							newNetwork = mergeWirelessNetworks(newNetwork, self.KnownNetworks[ssid])
					elif bssid in self.BSSIDToSSIDMap:
						continue
					elif ssid in self.KnownNetworks:								# this is a BSSID from a probe for an SSID we've seen before
						newNetwork = self.KnownNetworks[ssid]						# so pick up where we left off by using the curent state of the WirelessNetwork object
					elif bssid:
						newNetwork = eapeak.networks.WirelessNetwork(ssid)
						self.BSSIDToSSIDMap[bssid] = ssid
					newNetwork.addBSSID(bssid)
					
					self.KnownNetworks[ssid] = newNetwork
					del bssid, ssid
					break
				tmp = tmp.payload
				if tmp == None:
					break
			shouldStop = True
		if shouldStop:
			return
				
		# this section extracts useful EAP info
		cert_layer = None
		if 'EAP' in packet:
			fields = packet.getlayer('EAP').fields
			if fields['code'] not in [1, 2]:							# don't bother parsing through success and failures just yet.
				return
			eaptype = fields['type']
			for x in range(1, 4):
				addr = 'addr' + str(x)									# outputs addr1, addr2, addr3
				if not addr in packet.fields:
					return
			bssid = getBSSID(packet)
			if not bssid:
				return
			if bssid and not bssid in self.BSSIDToSSIDMap:
				self.BSSIDToSSIDMap[bssid] = bssid
				self.OrphanedBSSIDs.append(bssid)
				self.KnownNetworks[bssid] = eapeak.networks.WirelessNetwork(UNKNOWN_SSID_NAME)
				self.KnownNetworks[bssid].addBSSID(bssid)
			network = self.KnownNetworks[self.BSSIDToSSIDMap[bssid]]				# objects should be returned, network to client should affect the client object as still in the BSSIDMap
			bssid = getBSSID(packet)
			client_mac = getSource(packet)
			from_AP = False
			if client_mac == bssid:
				client_mac = getDestination(packet)
				from_AP = True
			if not bssid or not client_mac:
				return																# something went wrong
			if network.hasClient(client_mac):
				client = network.getClient(client_mac)
			else:
				client = eapeak.clients.WirelessClient(bssid, client_mac)
			if from_AP:
				network.addEapType(eaptype)
			elif eaptype > 4:
				client.addEapType(eaptype)
			elif eaptype == 3 and fields['code'] == 2:								# this parses NAKs and attempts to harvest the desired EAP types, RFC 3748
				if 'eap_types' in fields:
					for eap in fields['eap_types']:
						client.addEapType(eap)
					del eap
			if eaptype == 254 and packet.haslayer(EAP_Expanded):
				network.addExpandedVendorID(packet.getlayer(EAP_Expanded).vendor_id)
			if from_AP:													# from here on we look for things based on whether it's to or from the AP
				if packet.haslayer('LEAP'):
					leap_fields = packet.getlayer(LEAP).fields
					if 'data' in leap_fields and len(leap_fields['data']) == 8:
						client.addMSChapInfo(17, challenge = leap_fields['data'], identity = leap_fields['name'])
					del leap_fields
				elif packet.getlayer(EAP).payload.name in ['EAP_TLS', 'EAP_TTLS', 'PEAP', 'EAP_Fast']:
					eap_layer = packet.getlayer(EAP).payload
					conn_string = bssid + ' ' + client_mac
					frag_flag, len_flag = {'EAP_TLS':(64, 128), 'EAP_TTLS':(8, 16), 'PEAP':(16, 32), 'EAP_Fast':(8, 16)}[eap_layer.name]
					if eap_layer.flags & frag_flag and eap_layer.flags & len_flag:
						self.fragment_buffer[conn_string] = [eap_layer]
					elif eap_layer.flags & frag_flag:
						if conn_string in self.fragment_buffer:
							self.fragment_buffer[conn_string].append(eap_layer.payload)
					elif eap_layer.flags == 0 and conn_string in self.fragment_buffer:
						eap_layer = eap_layer.__class__(''.join([x.do_build() for x in self.fragment_buffer[conn_string]]) + eap_layer.payload.do_build())	# take that people trying to read my code! Spencer 1, you 0.
						del self.fragment_buffer[conn_string]
					if eap_layer.haslayer('TLSv1Certificate'):			# at this point, if possible, we should have a fully assembled packet
						cert_layer = eap_layer.getlayer(TLSv1Certificate)
					del eap_layer, conn_string, frag_flag, len_flag
				elif packet.haslayer('EAP_Expanded') and packet.getlayer('EAP_Expanded').vendor_type == 1 and packet.haslayer('WPS') and packet.getlayer('WPS').opcode == 4:
					try:
						wpsData = parseWPSData(packet.getlayer('WPS').data)
						if network.wpsData == None:
							network.wpsData = wpsData
						else:
							network.wpsData.update(wpsData)
					except:
						pass	

			else:
				if eaptype == 1 and 'identity' in fields:
					client.addIdentity(1, fields['identity'])
				if packet.haslayer('LEAP'):
					leap_fields = packet.getlayer(LEAP).fields
					identity = None
					if 'name' in leap_fields:
						identity = leap_fields['name']
						client.addIdentity(17, identity)
					if 'data' in leap_fields and len(leap_fields['data']) == 24:
						client.addMSChapInfo(17, response = leap_fields['data'], identity = identity)
					del leap_fields, identity
				elif packet.haslayer('EAP_Expanded') and packet.getlayer('EAP_Expanded').vendor_type == 1 and packet.haslayer('WPS') and packet.getlayer('WPS').opcode == 4:
					try:
						wpsData = parseWPSData(packet.getlayer('WPS').data)
						if client.wpsData == None:
							client.wpsData = wpsData
						else:
							client.wpsData.update(wpsData)
					except:
						pass											# data is corrupted
			network.addClient(client)
			if not cert_layer:
				shouldStop = True
		if shouldStop:
			return
			
		if cert_layer and 'certificate' in cert_layer.fields:
			cert_data = cert_layer.certificate[3:]
			tmp_certs = []
			while cert_data:
				if len(cert_data) < 4: break								# length and 1 byte are at least 4 bytes
				tmp_length = unpack('!I', '\x00' + cert_data[:3])[0]
				cert_data = cert_data[3:]
				if len(cert_data) < tmp_length: break						# I smell corruption
				tmp_certs.append(cert_data[:tmp_length])
				cert_data = cert_data[tmp_length:]
			for certificate in tmp_certs:
				try:
					certificate = X509.load_cert_string(certificate, X509.FORMAT_DER)
				except X509.X509Error:
					pass
				network.addCertificate(certificate)
		return

class CursesEapeakParsingEngine(EapeakParsingEngine):
	"""
	This engine contains additional methods necessary for the Curses UI.
	It is seperate from the other class to not degrade performance when
	Curses is not being used.
	"""
	def initCurses(self):
		"""
		This initializes the screen for curses useage.  It must be
		called before Curses can be used.
		"""
		self.user_marker_pos = 1							# used with curses
		self.curses_row_offset = 0							# used for marking the visible rows on the screen to allow scrolling
		self.curses_row_offset_store = 0					# used for storing the row offset when switching from detailed to non-detailed view modes
		self.curses_detailed = None							# used with curses
		self.screen = curses.initscr()
		curses.start_color()
		curses.init_pair(1, curses.COLOR_BLUE, curses.COLOR_WHITE)
		size = self.screen.getmaxyx()
		if size[0] < CURSES_MIN_Y or size[1] < CURSES_MIN_X:
			curses.endwin()
			return 1
		self.curses_max_rows = size[0] - 2					# minus 2 for the border on the top and bottom
		self.curses_max_columns = size[1] - 2
		
		self.screen.border(0)
		self.screen.addstr(2, TAB_LENGTH, 'EAPeak Capturing Live')
		self.screen.addstr(3, TAB_LENGTH, 'Found 0 Networks')
		self.screen.addstr(4, TAB_LENGTH, 'Processed 0 Packets')
		self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
		self.screen.refresh()
		try:
			curses.curs_set(1)
			curses.curs_set(0)
		except curses.error:								# ignore exceptions from terminals that don't support setting the cursor's visibility
			pass
		curses.noecho()
		curses.cbreak()
		self.curses_enabled = True
		self.curses_lower_refresh_counter = 1
		return 0
		
	def cursesInteractionHandler(self, garbage = None):
		"""
		This is a function meant to be run in a seperate thread to
		handle human interaction with the curses interface.
		"""
		while self.curses_enabled:
			c = self.screen.getch()
			if self.curses_lower_refresh_counter == 0:
				continue
			size = self.screen.getmaxyx()
			if size[0] < CURSES_MIN_Y or size[1] < CURSES_MIN_X:
				if not self.resizeDialog():
					break
				continue
			if c in [65, 117, 85] and len(self.KnownNetworks):		# 117 = ord('u')
				if self.curses_detailed:
					if self.curses_row_offset > 0:
						self.curses_row_offset -= 1
						self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY	# trigger a redraw by adjusting the counter
				else:
					self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, ' ' * len(USER_MARKER))
					if self.user_marker_pos == 1 and self.curses_row_offset == 0:
						pass	# ceiling
					elif self.user_marker_pos == 1 and self.curses_row_offset:
						self.curses_row_offset -= 1
						self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY
					else:
						self.user_marker_pos -= 1
					self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
			elif c in [66, 100, 68] and len(self.KnownNetworks):	# 100 = ord('d')
				if self.curses_detailed:
					self.curses_row_offset += 1
					self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY	# trigger a redraw by adjusting the counter
				else:
					if self.user_marker_pos + self.curses_row_offset == len(self.KnownNetworks):
						continue	# floor
					self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, ' ' * len(USER_MARKER))
					if self.user_marker_pos + USER_MARKER_OFFSET == self.curses_max_rows - 1:
						self.curses_row_offset += 1
						self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY
					else:
						self.user_marker_pos += 1
					self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
			elif c in [10, 105, 73]:	# 105 = ord('i')
				self.curses_row_offset_store = (self.curses_row_offset_store ^ self.curses_row_offset)
				self.curses_row_offset = (self.curses_row_offset ^ self.curses_row_offset_store)
				self.curses_row_offset_store = (self.curses_row_offset_store ^ self.curses_row_offset)
				if self.curses_detailed:
					self.curses_detailed = None
					self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
					self.screen.refresh()
					self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY	# trigger a redraw by adjusting the counter
				elif 0 <= (self.user_marker_pos - 1 + self.curses_row_offset) < len(self.KnownNetworks):
					self.curses_detailed = self.KnownNetworks.keys()[(self.user_marker_pos - 1) + self.curses_row_offset_store]	# self.curses_row_offset_store because we just exchanged the values so the original is here now
					self.screen.refresh()
					self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY	# trigger a redraw by adjusting the counter
			elif c in [113, 81]:		# 113 = ord('q')
				self.curses_lower_refresh_counter = 0
				subwindow = self.screen.subwin(6, 40, (self.curses_max_rows / 2 - 3), (self.curses_max_columns / 2 - 20))
				subwindow.erase()
				subwindow.addstr(2, 11, 'Really Quit? (y/N)')
				subwindow.border(0)
				subwindow.refresh()
				subwindow.overlay(self.screen)
				c = subwindow.getch()
				if c in [121, 89]:
					break
				self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY
			elif c in [104, 72]:		# 113 = ord('h')
				self.curses_lower_refresh_counter = 0
				subwindow = self.screen.subwin(10, 40, (self.curses_max_rows / 2 - 5), (self.curses_max_columns / 2 - 20))
				subwindow.erase()
				subwindow.addstr(1, 15, 'Help Menu')
				subwindow.addstr(2, 9, 'EAPeak Version: ' + __version__)
				subwindow.addstr(4, 2, 'i/Enter : Toggle View')
				subwindow.addstr(5, 2, 'q       : Quit')
				subwindow.addstr(6, 2, 'e       : Export Users For The')
				subwindow.addstr(7, 2, '          Selected Network')
				subwindow.border(0)
				subwindow.refresh()
				subwindow.overlay(self.screen)
				c = subwindow.getch()
				self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY
			elif c in [101, 69]:		# 101 = ord('e')
				usernames = []
				if self.curses_detailed in self.KnownNetworks:
					network = self.KnownNetworks[ self.curses_detailed ]
				else:
					network = self.KnownNetworks.values()[self.user_marker_pos - 1 + self.curses_row_offset]
				filename = network.ssid + '_users.txt'
				if network.clients:
					for client in network.clients.values():
						usernames.extend(client.identities.keys())
					try:
						filehandle = open(filename, 'w')
						filehandle.write("\n".join(usernames) + '\n')
						filehandle.close()
						message = 'Successfully Saved'
					except:
						message = 'Failed To Save'
				else:
					message = 'No ID Strings'
				self.curses_lower_refresh_counter = 0
				subwindow = self.screen.subwin(10, 40, (self.curses_max_rows / 2 - 5), (self.curses_max_columns / 2 - 20))
				subwindow.erase()
				subwindow.addstr(2, 2, 'File: ' + filename)
				subwindow.addstr(3, 2, message)
				subwindow.addstr(6, 8, 'Press Any Key To Continue')
				subwindow.border(0)
				subwindow.refresh()
				subwindow.overlay(self.screen)
				c = subwindow.getch()				
				self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY
		self.cleanupCurses()
		return
					
	def cursesScreenDrawHandler(self, save_to_xml):
		"""
		This is a function meant to be run in a seperate thread to
		handle drawing the curses interface to the screen.
		"""
		while self.curses_enabled:
			sleep(CURSES_REFRESH_FREQUENCY)
			if self.curses_lower_refresh_counter == 0:	# used to trigger pauses
				continue
			size = self.screen.getmaxyx()
			if size[0] < CURSES_MIN_Y or size[1] < CURSES_MIN_X:
				if not self.resizeDialog():
					break
				continue
			self.screen.refresh()
			self.screen.addstr(2, 4, 'EAPeak Capturing Live')			# this is all static, so don't use the messages queue
			self.screen.addnstr(3, 4, 'Found ' + str(len(self.KnownNetworks)) + ' Networks', 25)
			self.screen.addnstr(4, 4, "Processed {0} Packets".format(self.packetCounter), 30)
			self.screen.addstr(6, 4, 'Network Information:')
			if self.curses_lower_refresh_counter == CURSES_LOWER_REFRESH_FREQUENCY:
				self.curses_lower_refresh_counter = 1
				self.screen.move(7, 0)
				self.screen.clrtobot()
				if save_to_xml:
					self.exportXML()
			else:
				self.curses_lower_refresh_counter += 1
				continue
			
			messages = []
			ssids = self.KnownNetworks.keys()
			if self.curses_detailed and self.curses_detailed in self.KnownNetworks:
				network = self.KnownNetworks[ self.curses_detailed ]
				messages.append((TAB_LENGTH, 'SSID: ' + network.ssid))
				messages.append(CURSES_LINE_BREAK)
				
				messages.append((TAB_LENGTH, 'BSSIDs:'))
				for bssid in network.bssids:
					messages.append((TAB_DEPTH_2, bssid))
				messages.append(CURSES_LINE_BREAK)
				tmpEapTypes = []
				if network.eapTypes:
					for eType in network.eapTypes:
						if eType in EAP_TYPES:
							tmpEapTypes.append(EAP_TYPES[eType])
						else:
							tmpEapTypes.append(str(eType))
				if tmpEapTypes:
					messages.append((TAB_LENGTH, 'EAP Types: ' + ", ".join(tmpEapTypes)))
				else:
					messages.append((TAB_LENGTH, 'EAP Types: [ NONE ]'))
				tmpVendorIDs = []
				if network.expandedVendorIDs:
					for vType in network.expandedVendorIDs:
						if vType in EXPANDED_EAP_VENDOR_IDS:
							tmpVendorIDs.append(EXPANDED_EAP_VENDOR_IDS[vType])
						else:
							tmpVendorIDs.append(str(vType))
				if tmpVendorIDs:
					messages.append((TAB_LENGTH, 'Expanded Vendor IDs: ' + ", ".join(tmpVendorIDs)))
				del tmpEapTypes, tmpVendorIDs
				messages.append(CURSES_LINE_BREAK)
				if network.wpsData:
					the_cheese_stands_alone = True
					for piece in ['Manufacturer', 'Model Name', 'Model Number', 'Device Name']:
						if network.wpsData.has_key(piece):
							if the_cheese_stands_alone:
								messages.append((TAB_LENGTH, 'WPS Information:'))
								the_cheese_stands_alone = False
							messages.append((TAB_DEPTH_2, piece + ': ' + network.wpsData[piece]))
					if not the_cheese_stands_alone:
						messages.append(CURSES_LINE_BREAK)
					del the_cheese_stands_alone, piece
				if network.clients:
					messages.append((TAB_LENGTH, 'Clients:         '))
					clients = network.clients.values()
					for i in range(0, len(clients)):
						client = clients[i]
						messages.append((TAB_DEPTH_2, 'Client ' + str(i + 1) + ') MAC: ' + client.mac))
						if client.eapTypes:
							tmpEapTypes = []
							for y in client.eapTypes:
								if y in EAP_TYPES:
									tmpEapTypes.append(EAP_TYPES[y])
								else:
									tmpEapTypes.append(str(y))
							messages.append((TAB_DEPTH_2, 'EAP Types: ' + ", ".join(tmpEapTypes)))
							del tmpEapTypes
						else:
							messages.append((TAB_DEPTH_2, 'EAP Types: [ UNKNOWN ]'))
						if client.identities:
							messages.append((TAB_DEPTH_2, 'Identities:'))
						for ident, eap in client.identities.items():
							messages.append((TAB_DEPTH_3, '(' + EAP_TYPES[eap] + ') ' + ident))
						if client.mschap:
							first = True
							for value in client.mschap:
								if not 'r' in value: continue
								if first:
									messages.append((TAB_DEPTH_2, 'MSChap:'))
									first = False
								messages.append((TAB_DEPTH_3, 'EAP Type: ' + EAP_TYPES[value['t']] + ', Identity: ' + value['i']))
								messages.append((TAB_DEPTH_3, 'C: ' + value['c']))
								messages.append((TAB_DEPTH_3, 'R: ' + value['r']))
							del first
						if client.wpsData:
							the_cheese_stands_alone = True
							for piece in ['Manufacturer', 'Model Name', 'Model Number', 'Device Name']:
								if client.wpsData.has_key(piece):
									if the_cheese_stands_alone:
										messages.append((TAB_DEPTH_2, 'WPS Information:'))
										the_cheese_stands_alone = False
									messages.append((TAB_DEPTH_3, piece + ': ' + client.wpsData[piece]))
							del the_cheese_stands_alone, piece
						messages.append(CURSES_LINE_BREAK)
					messages.pop()	# trash the trailing line break
					del clients
				else:
					messages.append((TAB_LENGTH, 'Clients: [ NONE ]'))
				if network.x509certs:
					messages.append(CURSES_LINE_BREAK)
					messages.append((TAB_LENGTH, 'Certificates:'))
					i = 1
					for cert in network.x509certs:
						messages.append((TAB_DEPTH_2, 'Certificate ' + str(i) + ') Expiration Date: ' + str(cert.get_not_after())))
						data = cert.get_issuer()
						messages.append((TAB_DEPTH_2, 'Issuer:'))
						for X509_Name_Entry_inst in data.get_entries_by_nid(13): 	# 13 is CN
							messages.append((TAB_DEPTH_3, 'CN: ' + X509_Name_Entry_inst.get_data().as_text()))
						for X509_Name_Entry_inst in data.get_entries_by_nid(18): 	# 18 is OU
							messages.append((TAB_DEPTH_3, 'OU: ' + X509_Name_Entry_inst.get_data().as_text()))
						data = cert.get_subject()
						messages.append((TAB_DEPTH_2, 'Subject:'))
						for X509_Name_Entry_inst in data.get_entries_by_nid(13): 	# 13 is CN
							messages.append((TAB_DEPTH_3, 'CN: ' + X509_Name_Entry_inst.get_data().as_text()))
						for X509_Name_Entry_inst in data.get_entries_by_nid(18): 	# 18 is OU
							messages.append((TAB_DEPTH_3, 'OU: ' + X509_Name_Entry_inst.get_data().as_text()))
						del data
						i += 1
						messages.append(CURSES_LINE_BREAK)
					messages.pop() # trash the trailing line break
				# message queue is built, now adjust it to be printed to the screen
				max_offset = len(messages) - (self.curses_max_rows - 7)
				if max_offset < 0:
					max_offset = 0
				if self.curses_row_offset > max_offset:
					self.curses_row_offset = max_offset
				del max_offset
				for i in range(0, self.curses_row_offset):
					messages.pop(0)
				self.screen.border(0)
			else:
				messages.append((TAB_DEPTH_2, 'SSID:' + ' ' * (SSID_MAX_LENGTH + 2) + 'EAP Types:'))
				if self.curses_row_offset:
					messages.append((TAB_DEPTH_2, '[ MORE ]'))
				else:
					messages.append((TAB_DEPTH_2, '        '))
				for i in range(self.curses_row_offset, len(ssids)):
					if len(messages) > self.curses_max_rows - 8:
						messages.append((TAB_DEPTH_2, '[ MORE ]'))
						break
					network = self.KnownNetworks[ssids[i]]
					tmpEapTypes = []
					if network.eapTypes:
						for eType in network.eapTypes:
							if eType in EAP_TYPES:
								tmpEapTypes.append(EAP_TYPES[eType])
							else:
								tmpEapTypes.append(str(eType))
					if i < 9:
						messages.append((TAB_DEPTH_2, str(i + 1) + ')  ' + network.ssid + ' ' * (SSID_MAX_LENGTH - len(network.ssid) + 3) + ", ".join(tmpEapTypes)))
					else:
						messages.append((TAB_DEPTH_2, str(i + 1) + ') ' + network.ssid + ' ' * (SSID_MAX_LENGTH - len(network.ssid) + 3) + ", ".join(tmpEapTypes)))
				if not len(messages) > self.curses_max_rows - 2:
					messages.append((TAB_DEPTH_2, '        '))
				self.screen.border(0)
				self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
			line = 7
			try:
				for message in messages:
					self.screen.addnstr(line, message[0], message[1], self.curses_max_columns - message[0])
					line += 1
					if line > self.curses_max_rows: break	# fail safe
			except curses.error:
				pass
		self.cleanupCurses()
		return
		
	def parseLiveCapture(self, packet, quite = True):
		"""
		Function is meant to be passed to Scapy's sniff() function similar to:
		lambda packet: eapeakParser.parseLiveCapture(packet, use_curses)
		
		sniff(iface = 'mon0', prn = lambda packet: eapeakParser.parseLiveCapture(packet, False) )
		"""
		self.parseWirelessPacket(packet)
		if self.curses_enabled or quite:
			return
		sys.stdout.write('Packets: ' + str(self.packetCounter) + ' Wireless Networks: ' + str(len(self.KnownNetworks)) + '\r')
		sys.stdout.flush()
				
	def resizeDialog(self):
		"""
		This is a dialog to be used to warn the user when a screen
		resize event has been used to make the screen to small for use.
		"""
		self.curses_lower_refresh_counter = 0
		size = self.screen.getmaxyx()
		self.screen.erase()
		self.screen.addstr(0, 0, 'Screen Too Small, Requires')
		self.screen.addstr(1, 0, 'At Least: ' + str(CURSES_MIN_X) + 'x' + str(CURSES_MIN_Y))
		self.screen.refresh()
		while size[0] < CURSES_MIN_Y or size[1] < CURSES_MIN_X:
			if size[0] < 2 or size[1] < 26:
				return False
			size = self.screen.getmaxyx()
			self.screen.refresh() # this has to be here
		self.screen.erase()
		self.screen.refresh()
		self.curses_lower_refresh_counter = CURSES_LOWER_REFRESH_FREQUENCY	# trigger a redraw by adjusting the counter
		self.curses_max_rows = size[0] - 2					# minus 2 for the border on the top and bottom
		self.curses_max_columns = size[1] - 2
		return True
		
	def cleanupCurses(self):
		"""
		This cleans up the curses interface and resets things back to
		normal.
		"""
		if not self.curses_enabled: return
		self.screen.erase()
		del self.screen
		curses.endwin()
		curses.echo()
		self.curses_enabled = False
