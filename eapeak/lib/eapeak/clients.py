"""
	-*- coding: utf-8 -*-
	clients.py
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

from scapy.layers.l2 import eap_types as EAP_TYPES
from binascii import hexlify
from base64 import standard_b64encode as b64encode
from xml.sax.saxutils import escape as XMLEscape
EAP_TYPES[0] = 'NONE'

class WirelessClient:
	"""
	This is an object representing a wireless client.  The MAC address,
	and BSSID are both unique.
	"""
	authenticated = False
	mac = ''	# this is unique
	bssid = ''	# this is also unique
	
	def __init__(self, bssid, mac):
		self.bssid = bssid
		self.mac = mac
		self.identities = {}											# eaptypes keyed by identities (probably won't have more than one or two, but the identities are unique, allowing for multiple usernames)
		self.eapTypes = []
		self.datastore = {}												# I love metasploit
		self.mschap = []												# holds respObj dictionaries, keys are 't' for eap type (int), 'c' for challenge (str), 'r' for response (str), 'i' for identity (str)
		self.wpsData = None												# this will be changed to an instance of eapeak.parse.wpsDataHolder or a standard dictionary
	
	def addEapType(self, eaptype):
		"""
		Add an eap type to the internal list.
		"""
		if eaptype not in self.eapTypes and eaptype > 4:
			self.eapTypes.append(eaptype)

	def addIdentity(self, eaptype, identity):
		"""
		Adds identity strings with their associated EAP type that they
		were discovered with.
		"""
		if not identity in self.identities.keys() and identity:
			self.identities[identity] = eaptype
			
	def addMSChapInfo(self, eaptype, challenge = None, response = None, identity = None):
		"""
		Adds information to the internal "mschap" list which contains
		dictionaries for each set with keys of:
			't'	eap type (integer)
			'c' challenge (packed binary string)
			'r' response (packed binary string)
			'i' identity (string)
		Challenge and Response strings are packed binary,
		NOT 00:00:00:00:00:00:00:00 or 0000000000000000
		"""
		if not identity:
			identity = 'UNKNOWN'

		if challenge:							
			challenge = hexlify(challenge)
			challenge = ":".join([challenge[y:y+2] for y in range(0, len(challenge), 2)])
			self.mschap.append({'t':eaptype, 'c':challenge, 'i':identity})
		if response and len(self.mschap):								# we're adding a response string, make sure we have at least one challenge string
			response = hexlify(response)
			response = ":".join([response[y:y+2] for y in range(0, len(response), 2)])
			for value in self.mschap:
				if not 'r' in value:
					continue
				if response == value['r'] and identity == value['i']:	# we already have this particular identity and response so don't store it again, don't check the challenge because chances are it's legit and should be random, resulting in a different response
					return												# we should only see this in cases that the attacker is supplying the same challenge everytime, *cough* free radius WPE *cough*
			respObj = self.mschap[len(self.mschap) - 1]					# get the last response dictionary object
			if identity and identity != respObj['i']:					# we have a supplied identity but they don't match
				return 1
			if not 'r' in respObj:										# make sure we don't over write one (that would be bad)
				respObj['r'] = response
			else:
				return 2												# we seem to have received 2 response strings without a challenge in between

	def show(self, tabs = 0):
		"""
		This returns a string of human readable information describing
		the client object, tabs is an optional offset.
		"""
		output = ('\t' * tabs) + 'MAC: ' + self.mac + '\n'
		output += ('\t' * tabs) + 'Associated BSSID: ' + self.bssid + '\n'
		
		if self.identities:
			output += ('\t' * tabs) + 'Identities:\n\t' + ('\t' * tabs) + ("\n\t" + ('\t' * tabs)).join(self.identities.keys()) + '\n'
			
		if self.eapTypes:
			output += ('\t' * tabs) + 'EAP Types:\n'
			for eapType in self.eapTypes:
				if eapType in EAP_TYPES.keys():
					output += ('\t' * tabs) + '\t' + EAP_TYPES[eapType] + '\n'
				else:
					output += ('\t' * tabs) + '\tEAP Type #' + str(eapType) + '\n'
		if self.mschap:
			the_cheese_stands_alone = True
			for respObj in self.mschap:
				if not 'r' in respObj:									# no response? useless
					continue
				if the_cheese_stands_alone:
					output += ('\t' * tabs) + 'MS Chap Challenge & Responses:\n'
					the_cheese_stands_alone = False
				output += ('\t' * tabs) + '\tEAP Type: ' + EAP_TYPES[respObj['t']]
				if respObj['i']:
					output += ', Identity: ' + respObj['i']
				output += '\n'
				output += ('\t' * tabs) + '\t\tC: ' + respObj['c'] + '\n' + ('\t' * tabs) + '\t\tR: ' + respObj['r'] + '\n'
		if self.wpsData:
			the_cheese_stands_alone = True
			for piece in ['Manufacturer', 'Model Name', 'Model Number', 'Device Name']:
				if self.wpsData.has_key(piece):
					if the_cheese_stands_alone:
						output += ('\t' * tabs) + 'WPS Information:\n'
						the_cheese_stands_alone = False
					output += ('\t' * tabs) + '\t' + piece + ': ' + self.wpsData[piece] + '\n'
		return output.rstrip()

	def getXML(self):
		"""
		This returns the XML representation of the client object.
		"""
		from xml.etree import ElementTree
		root = ElementTree.Element('wireless-client')
		ElementTree.SubElement(root, 'client-mac').text = self.mac
		ElementTree.SubElement(root, 'client-bssid').text = self.bssid
		ElementTree.SubElement(root, 'eap-types').text = ",".join([str(i) for i in self.eapTypes])
		
		for identity, eaptype in self.identities.items():
			tmp = ElementTree.SubElement(root, 'identity')
			tmp.set('eap-type', str(eaptype))
			tmp.text = XMLEscape(identity)
			
		for respObj in self.mschap:
			if not 'r' in respObj: continue
			tmp = ElementTree.SubElement(root, 'mschap')
			tmp.set('eap-type', str(respObj['t']))
			tmp.set('identity', XMLEscape(respObj['i']))
			ElementTree.SubElement(tmp, 'challenge').text = respObj['c']
			ElementTree.SubElement(tmp, 'response').text = respObj['r']
		
		if self.wpsData:
			wps = ElementTree.SubElement(root, 'wps-data')
			for info in ['manufacturer', 'model name', 'model number', 'device name']:
				if self.wpsData.has_key(info):
					tmp = ElementTree.SubElement(wps, info.replace(' ', '-'))
					tmp.text = self.wpsData[info]
			for info in ['uuid', 'registrar nonce', 'enrollee nonce']:	# values that should be base64 encoded
				if self.wpsData.has_key(info):
					tmp = ElementTree.SubElement(wps, info.replace(' ', '-'))
					tmp.set('encoding', 'base64')
					tmp.text = b64encode(self.wpsData[info])
		return root
