#!/usr/bin/env python
#
# beacon_flood_raw.py - Simple IEEE 802.11
#	beacon flooder using pylorcon2's raw
#	sending capabilities.
#
# brad.antoniewicz@foundstone.com
#
#

import getopt
import sys
import string

from time import sleep

import PyLorcon2

def usage():
	print "\t-i <int> \tInterface"
	print "\t-c <channel> \tChannel"
	print "\nExample: "
	print "\t",sys.argv[0],"-i wlan0 -c 11\n"


'''
	main
'''

print sys.argv[0]," - Simple 802.11 beacon flooder"
print "-----------------------------------------------------\n" 

# Beacon interval 
interval = 100

# Raw packet bytes (from capture_example.c included within LORCON)
packet = 	"\x80\x00\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\x00\x0f\x66\xe3\xe4\x03" \
		"\x00\x0f\x66\xe3\xe4\x03\x00\x00" \
		"\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\x64\x00\x11\x00\x00\x0f\x73\x6f" \
		"\x6d\x65\x74\x68\x69\x6e\x67\x63" \
		"\x6c\x65\x76\x65\x72\x01\x08\x82" \
		"\x84\x8b\x96\x24\x30\x48\x6c\x03" \
		"\x01\x01\x05\x04\x00\x01\x00\x00" \
		"\x2a\x01\x05\x2f\x01\x05\x32\x04" \
		"\x0c\x12\x18\x60\xdd\x05\x00\x10" \
		"\x18\x01\x01\xdd\x16\x00\x50\xf2" \
		"\x01\x01\x00\x00\x50\xf2\x02\x01" \
		"\x00\x00\x50\xf2\x02\x01\x00\x00" \
		"\x50\xf2\x02"

interface = channel = None 

'''
        This handles all of the command line arguments
'''


try:
	opts, args = getopt.getopt(sys.argv[1:], "i:c:h",[])
except getopt.GetoptError:
	usage()
	sys.exit(-1)	

for o,a in opts:
	if o == "-i":
		interface = a
	if o == "-c":
		channel = string.atoi(a)
	if o == "-h":
		usage()

if ( (interface is None) or (channel is None) ):
	print "ERROR: Interface or channel not set (see -h for more info)"
	sys.exit(-1)

print "[+] Using interface",interface

'''
	The following is all of the standard interface, driver, and context setup
'''

# Automatically determine the driver of the interface

try:
	driver, description = PyLorcon2.auto_driver(interface)
	if driver is not None:
		print "[+]\t Driver:",driver
except:
	print "[!] Could not determine the driver for",interface
	sys.exit(-1)

# Create LORCON context
try:
	ctx = PyLorcon2.Context(interface)
except:
	print "[!]\t Failed to create context"
	sys.exit(-1)

# Create Monitor Mode Interface

try:
	ctx.open_injmon()
	vap = ctx.get_vap()
	if vap is not None:	
		print "[+]\t Monitor Mode VAP:",vap
except:
	print "[!]\t Could not create Monitor Mode interface!"
	sys.exit(-1)

# Set the channel we'll be injecting on

try:
	ctx.set_channel(channel)
	print "[+]\t Using channel:",channel,"\n"
except:
	print "[!]\t Could not set channel!"
	sys.exit(-1)	

'''
	The following is the packet creation and sending code
'''

# Keep sending frames until interrupted
count = 0
while 1:

	try:
		ctx.send_bytes(packet)
		sleep(interval/1000.0)
		print "[+] Sent",count,"frames, Hit CTRL + C to stop...\r",
		sys.stdout.flush()
				
	except:
		print "\n[!] Exiting..."
		sys.exit(0)
	
	count+=1


'''
	The following is all of the standard cleanup stuff
'''

# Close the interface
ctx.close()



