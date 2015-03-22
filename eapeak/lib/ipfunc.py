"""
Created By: Spencer McIntyre
September 2009
	   
	Copyright 2009 Spencer McIntyre
   
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

	Distributed as part of EAPeak, http://www.securestate.net
	This module contains misc. ip related functions.
"""

__doc__ = 'Distributed as part of CORI, http://sourceforge.net/projects/cori-python/\n\nThis module contains misc. ip related functions.'
__version__ = '1.8'
numbers = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']

def bin(n):												# Necessary for Python versions < 2.6 which are stupid, update to the latest version you lazy bastards.
	"""
	Necessary for Python versions < 2.6 which are stupid, update to the latest version you lazy bastards.
	"""
	x, y = 1, 0
	while x < n:
		x = x << 1
		y += 1
	if x == n:
		tmp = [str((n >> y) & 1) for y in range(y, -1, -1)]				# this is for 1, 2, 4, 8, 16 etc (all those natural byte numbers)
	else:
		tmp = [str((n >> y) & 1) for y in range((y - 1), -1, -1)]
	binary = "".join(tmp)
	binary = "0b" + binary
	return binary
	
class ParseError(Exception):							# This is an Exception to be raised if the parseDash or parseCIDR methods detect invalid syntax.  Error numbers 10 through 19 are Dashed notation errors, 20 through 29 are CIDR notation errors.
	"""
	This is an Exception to be raised if the parseDash or parseCIDR methods detect invalid syntax.  Error numbers 10 through 19 are Dashed notation errors, 20 through 29 are CIDR notation errors.
	"""
	errDict = {	1:'Range Format Not Recognized',
				10:'Invalid Format In Dash Notation',
				11:'An Octet Is Not Within The Permissible Range (0-255)',
				12:'Invalid Number Of Octets In Range',
				13:'An Invalid Character Has Been Dected Within The Range',
				20:'Invalid Format In CIDR Notation',
				21:'The Network Prefix Is Not Within The Permissible Range (1 - 32)',
				22:'The IP Address Is Invalid',
				23:'The Network Prefix Results In To Many Items For Python'	}
	def __init__(self, msg):
		if msg in self.errDict.keys():
			self.msg = self.errDict[msg]
		else:
			self.msg = 'Undefined Error Code: ' + str(msg)
	def __str__(self):
		return repr(self.msg)

def sanitizeMAC(addr, ciscoFormat = False):				# This function will return True if the string passed to it looks like a real MAC address.  ciscoFormat defines whether to expect Cisco\'s xxxx.xxxx.xxxx format.
	"""
	This function will return True if the string passed to it looks like a real MAC address.  ciscoFormat defines whether to expect Cisco\'s xxxx.xxxx.xxxx format.
	"""
	if ciscoFormat:
		char = '.'
		len0 = 3
		len1 = 4
		top = 65536
	else:
		char = ':'
		len0 = 6
		len1 = 2
		top = 256
	addr = addr.split(char)
	if len(addr) != len0:
		return False
	for part in addr:
		if len(part) != len1:
			return False
		try:
			if not int(part, 16) < top:
				return False
		except ValueError:
			return False
	return True #if still executing it looks legit

def sanitizeIP(addr):									# This function will return True if the string passed to it looks like a real IP address.
	"""
	This function will return True if the string passed to it looks like a real IP address.
	"""
	addr = addr.split('.')
	if len(addr) != 4:
		return False
	for i in range(len(addr)):
		try:
			int(addr[i])
		except ValueError:
			return False
		if int(addr[i]) < 0 or int(addr[i]) > 255:
			return False
	return True
	
def parseDash(addr):									# This function takes an ip address in dashed notations such as "10.0.1-4.1-254" and returns a list of all of the ip addresses.
	"""
	This function takes an ip address in dashed notations such as "10.0.1-4.1-254" and returns a list of all of the ip addresses.
	"""
	addr = filter(lambda x: x in numbers + ['.', '-', '*'], addr)
	addr = addr.split('.')
	ipList = []
	addrList = []

	if len(addr) == 4:
		for i in range(0,4):
			try:
				if addr[i].find('-') != -1:
					templist = addr[i].split('-')
					if int(templist[1])>=int(templist[0]):
						addrList.append(templist[0])
						addrList.append(templist[1])
					else:
						addrList.append(templist[1])
						addrList.append(templist[0])
				elif addr[i].find('*') != -1:
					addrList.append('0')
					addrList.append('255')
				elif 0 <= int(addr[i]) < 256:
					addrList.append(addr[i])
					addrList.append(addr[i])
				else:
					raise ParseError(11)
			except:
				raise ParseError(13)
	else:
		raise ParseError(12)
				
	for counta in range(int(addrList[0]), int(addrList[1]) + 1):
		for countb in range(int(addrList[2]), int(addrList[3]) + 1):
			for countc in range(int(addrList[4]), int(addrList[5]) + 1):
				for countd in range(int(addrList[6]), int(addrList[7]) + 1):
					ipList.append(str(counta) + '.' + str(countb) + '.' + str(countc) + '.' + str(countd))
	return ipList
	
def parseCIDR(addr, hostsOnly = True):					# This function takes an ip address in CIDR notations such as "10.0.0.0/24" and returns a list of all of the  ip addresses.  The hostsOnly option returns only valid host IP addresses (network and broadcast addresses are removed).
	"""
	This function takes an ip address in CIDR notations such as "10.0.0.0/24" and returns a list of all of the  ip addresses.  If there is an error it will return an empty list.  The hostsOnly option returns only valid host IP addresses (network and broadcast addresses are removed).
	"""
	from struct import pack
	from socket import inet_ntoa
	addr = addr.split('/')
	try:
		if not addr[1].isdigit():
			raise ParseError(20)
	except IndexError:
		raise ParseError(20)
	try:
		addr, net = addr[0], int(addr[1])
	except ValueError:
		raise ParseError(20)
	if not -1 < net < 33:
		raise ParseError(21)
	if not sanitizeIP(addr):
		raise ParseError(22)
	ipaddress = ''
	for part in addr.split('.'):
		part = bin(int(part))[2:]
		while len(part) < 8:
			part = '0' + part
		ipaddress += part
	ipprefix, ipsuffix = ipaddress[:net], ipaddress[net:]
	
	del ipaddress, part
	
	ipList = []
	try:
		for i in range(0, 2**(len(ipsuffix))):
			i = bin(i)[2:]
			while len(i) < (32 - net):
				i = '0' + i
			binary = ipprefix + i
			ipaddress = pack('B', int(binary[0:8], 2)) + pack('B', int(binary[8:16], 2)) + pack('B', int(binary[16:24], 2)) + pack('B', int(binary[24:32], 2))
			ipList.append(inet_ntoa(ipaddress))
	except OverflowError:
		raise ParseError(23)
	if hostsOnly and net < 31:														# Remove network and broadcast
		ipList.pop(0)
		ipList.pop()
	return ipList
	
def parseNetwork(addr):									# This function will attempt to guess the type of format the range is in and use the corresponding function to parse it.  This is a convience feature to act as a catch all.
	"""
	This function will attempt to guess the type of format the range is in and use the corresponding function to parse it.  This is a convience feature to act as a catch all.
	"""
	if '/' in addr:
		return parseCIDR(addr)
	elif '-' in addr or '*' in addr:
		return parseDash(addr)
	elif sanitizeIP(addr):
		return [addr]
	else:
		raise ParseError(1)
	
def getflags(flags):									# This function will take the binary form of the flags in the form of a byte within a TCP segment and return a list of flags
	"""
	This function will take the binary form of the flags in the form of a byte within a TCP segment and return a list of flags
	"""
	flagdict = {128:'RE0', 64:'RE1', 32:'URG', 16:'ACK', 8:'PSH', 4:'RST', 2:'SYN', 1:'FIN' }#the first two are reserved
	flags = struct.unpack('B', flags)[0]
	flagsindata = []
	flaglist = flagdict.keys()
	flaglist.sort()
	flaglist.reverse()
	for i in flaglist:
		if flags - i >= 0:
			flagsindata.append(flagdict[i])
			flags = flags - i	
	return flagsindata

def cidrToNetmask(ip):									# This will take a network such as 10.0.0.0/13 and return the network 10.0.0.0 and netmask 255.248.0.0
	"""
	This will take a network such as 10.0.0.0/13 and return the network 10.0.0.0 and netmask 255.248.0.0
	"""
	network, cidr = ip.split('/')
	netmask, i, cidr = '', 0, int(cidr)
	while i < (cidr / 8):
		netmask += '255.'
		i += 1
	if (cidr % 8) > 0:
		netmask += str(256 - (2 ** (8 - (cidr % 8))))
	else:
		netmask = netmask[:-1] #cut trailing .
	while len(netmask.split('.')) < 4:
		netmask += '.0'
	return network, netmask

def wiresharkHexToBinary(string):						# This allows you to copy the "Bytes (Hex Stream)" field from wireshark and convert it to actual packed binary for quick reuse.
	"""
	This allows you to copy the "Bytes (Hex Stream)" field from wireshark and convert it to actual packed binary for quick reuse.
	"""
	from struct import pack
	i = 0
	newString = ""
	while i < len(string):
		newString += pack('B', int(string[i : i + 2], 16))
		i += 2
	return newString

def fuzzPackedBinary(binary):							# Fuzz a packed binary string with arbitrary data.  No analysis takes place.
	"""
	Fuzz a packed binary string with arbitrary data.  No analysis takes place.
	"""
	from random import randint
	from struct import pack
	action = randint(0, 2)
	length = len(binary)
	if action < 0:
		loop = length / 10
		while loop:
			length = len(binary)
			position = randint(0, length - 1)
			newdata = pack('B', randint(0, 255))
			if position == (length - 1):					# If the last byte was chosen
				binary = binary[:position] + newdata
			else:
				binary = binary[:position] + newdata + binary[position + 1:]
			loop -= 1
	else:
		add = randint(0, 1)
		if add:
			position = randint(0, length)
			newdata = pack('B', randint(0, 255))
			newdata = newdata * {0:1, 1:10, 2:100, 3:500}[randint(0,3)]
			binary = binary[:position] + newdata + binary[position:]
		else:
			start = randint(0, length - 2)
			end = randint(start, length - 1)
			binary = binary[start:end]
	return binary

def getHwAddr(ifname):									# Return the MAC address associated with a network interface, available only on Linux
	"""
	Return the MAC address associated with a network interface, available only on Linux
	"""
	from socket import socket, AF_INET, SOCK_DGRAM
	from fcntl import ioctl
	from struct import pack
	s = socket(AF_INET, SOCK_DGRAM)
	info = ioctl(s.fileno(), 0x8927,  pack('256s', ifname[:15]))
	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
