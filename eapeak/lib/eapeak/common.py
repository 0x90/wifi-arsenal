"""
	-*- coding: utf-8 -*-
	common.py
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

from os import listdir
from os.path import isdir
from fcntl import ioctl
from struct import pack, unpack
from socket import socket, AF_INET, SOCK_DGRAM

# various #define statments from Kernel Header files
SIOCSIWFREQ	= 0x8B04
SIOCGIWFREQ	= 0x8B05
SIOCGIFADDR = 0x8915

# from linux/if.h
IFNAMSIZ = 16

BSSID_SEARCH_RECURSION = 3
BSSIDPositionMap = { 0:'3', 1:'1', 2:'2', 8:'3', 9:'1', 10:'2' }
SourcePositionMap = { 0:'2', 1:'2', 2:'3', 8:'2', 9:'2', 10:'3' }
DestinationPositionMap = { 0:'1', 1:'3', 2:'1', 8:'1', 9:'3', 10:'1' }
FreqToChanMap = { 	2412:1, 2417:2, 2422:3, 2427:4, 2432:5, 2437:6, 2442:7,
					2447:8, 2452:9, 2457:10, 2462:11, 2467:12, 2472:13, 2484:14	}
EXPANDED_EAP_VENDOR_IDS = { 0x137:'Microsoft', 0x372a:'WPS' }

def getBSSID(packet):
	"""
	Returns a BSSID from a Scapy packet object, returns None on failure.
	"""
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not 'FCfield' in tmppacket.fields:
			tmppacket = tmppacket.payload
			continue
		if tmppacket.fields['FCfield'] in BSSIDPositionMap:
			if tmppacket.fields.has_key('addr' + BSSIDPositionMap[tmppacket.fields['FCfield']]):
				return tmppacket.fields['addr' + BSSIDPositionMap[tmppacket.fields['FCfield']]]
			else:
				return None # something is invalid
		else:
			return None # somthing is invalid
	return None
	
def getSource(packet):
	"""
	Returns the source MAC address from a Scapy packet object, returns
	None on failure.
	"""
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not 'FCfield' in tmppacket.fields:
			tmppacket = tmppacket.payload
			continue
		if tmppacket.fields['FCfield'] in SourcePositionMap:
			if tmppacket.fields.has_key('addr' + SourcePositionMap[tmppacket.fields['FCfield']]):
				return tmppacket.fields['addr' + SourcePositionMap[tmppacket.fields['FCfield']]]
			else:
				return None # something is invalid
		else:
			return None # somthing is invalid
	return None
	
def getDestination(packet):
	"""
	Returns the destination MAC address from a Scapy packet object,
	returns None on failure.
	"""
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not 'FCfield' in tmppacket.fields:
			tmppacket = tmppacket.payload
			continue
		if tmppacket.fields['FCfield'] in DestinationPositionMap:
			if tmppacket.fields.has_key('addr' + DestinationPositionMap[tmppacket.fields['FCfield']]):
				return tmppacket.fields['addr' + DestinationPositionMap[tmppacket.fields['FCfield']]]
			else:
				return None # something is invalid
		else:
			return None # somthing is invalid
	return None
	
def checkInterface(ifname):
	"""
	This is a modified function from one I found online to get an IP.
	Only Linux is supported.
	errDict = {
		-2: "Unsupported OS",
		-1: "Unknown",
		0: "Iface Exists, Has IP",
		1: "Iface Exists, No IP",
		2: "Iface Does Not Exist"
	}
	"""
	from os import name
	if name != 'posix':
		return -2
	sock = socket(AF_INET, SOCK_DGRAM)
	try:
		addr = ioctl(sock.fileno(), SIOCGIFADDR, pack('256s', ifname[:15]))[20:24]
	except IOError as err:
		if err.errno == 99:
			return 1
		elif err.errno == 19:
			return 2
		return -1
	return 0

def getInterfaceChannel(ifname, returnFreq = False):
	"""
	This Provides a pythonic interface for querying the channel or
	frequency that a wireless card is using.  To obtain the value as a
	frequency set returnFreq to True.
	Returns channel or frequency on success, negative number on error.
	"""
	if not checkInterface(ifname) in [0, 1]:
		return -1
	packstr = str(IFNAMSIZ) + 'sh14x'
	sock = socket(AF_INET, SOCK_DGRAM)
	try:
		freq = unpack(packstr, ioctl(sock.fileno(), SIOCGIWFREQ, pack(packstr, ifname, 0)))[1] # this is in MHz
	except IOError:
		return -2
	if returnFreq:
		return freq
	if freq in FreqToChanMap:
		return FreqToChanMap[freq]
	else:
		return -2

def setInterfaceChannel(ifname, channel, zealous = False):
	"""
	This provides a pythonic interface for changing the the channel on a
	wireless interface.  In addition to configuring the wireless card
	via channel, the user can also specify a frequency in MHz which will
	be translated to a channel. The zealous option addresses a common
	problem when using airmon-ng  to configure the monitor interface.
	This problem occurs when an interface such as mon0 is being used for
	injection however, the channel must be set on wlan0.
	Returns True on success, False otherwise.
	"""
	if (2411 < channel < 2485) and channel in FreqToChanMap:	# this will allow the channel to be set from a frequency in MHz
		channel = FreqToChanMap[channel]
	if not 0 < channel < 15:
		return False
	if not checkInterface(ifname) in [0, 1]:
		return False
	packstr = str(IFNAMSIZ) + 'sb15x'
	sock = socket(AF_INET, SOCK_DGRAM)
	
	if zealous and isdir('/sys/class/net/' + ifname + '/phy80211/device/net'):
		interfaces = listdir('/sys/class/net/' + ifname + '/phy80211/device/net')
		if ifname in interfaces:
			interfaces.remove(ifname)
		interfaces.insert(0, ifname)
	else:
		interfaces = [ ifname ]
	for ifname in interfaces:
		try:
			result = ioctl(sock.fileno(), SIOCSIWFREQ, pack(packstr, ifname, channel))
		except IOError as err:
			return False
		result = (unpack(packstr, result)[1] == channel and getInterfaceChannel(ifname) == channel)
		if result or not zealous:
			return result
	return False
