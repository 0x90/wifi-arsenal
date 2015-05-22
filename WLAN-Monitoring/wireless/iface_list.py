#!/usr/bin/env python

try:
	import subprocess
except ImportError, e:
	pass
	
class GetInterfaceList(object):
	def __init__(self):
		# Initiating an empty tuple to hold available wireless interfaces
		self.interfaces = ()
		# Calls 'iwconfig' command in system and pipes the output as stdout.				 
		proc = subprocess.Popen(['/sbin/iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.stdout, self.stderr =  proc.communicate()
		newline = self.stdout.count('\n')
		lines = []	
	
	# function to handle the output from 'iwconfig' and return tuple of available interfaces with their corresponding mode of operation.
	def getIface(self):
		lines = self.stdout.split('\n          \n')
		lines.remove('')
		for i in range(len(lines)):
			words = lines[i].split()
			interface = words[0]
			if "Monitor" in lines[i]:
				iface_mode = words[3].split(':')
			else:
				iface_mode = words[4].split(':')
			mode = iface_mode[1].lower()
			# Since we cannot add elements into tuple, we first convert it into list, insert elements and finally, convert it back into tuple.
			self.interfaces = list(self.interfaces)
			self.interfaces.insert(i, [interface, mode])
			self.interfaces = tuple(self.interfaces)
		# Returns the tuple of interfaces to caller's location
		return self.interfaces

class ListInterfaces(object):
	def getAllInterfaces(self):
		ifaces = []
		proc2 = subprocess.Popen(['/sbin/ifconfig', '-s'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = proc2.communicate()
		lines = stdout.split('\n')
		lines.remove(lines[0])
		lines.remove('')
		for i in range(len(lines)):
			words = lines[i].split()
			iface = words[0]
			ifaces.append(iface)
		wireless_ifaces = GetInterfaceList().getIface()
		for i,m in wireless_ifaces:
			if i in ifaces:
				ifaces.remove(i)
			
		return ifaces

'''
if __name__ == '__main__':
	getifacelist = ListInterfaces().getAllInterfaces()
	for iface in getifacelist:
		print "Interface: %s" % iface
		
	getwiface = GetInterfaceList().getIface()
	for wiface, mode in getwiface:
		print "Wireless interface: %s, Mode: %s" % (wiface, mode)
'''
