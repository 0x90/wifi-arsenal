#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import argparse
import sys
import signal
import threading
import datetime
from subprocess import Popen, PIPE
DN = open(os.devnull, 'w')

parser = argparse.ArgumentParser()
parser.add_argument("-j", "--join", help="Show all devices that join the network and when they did it (goes by DHCP packets)", action="store_true")
args = parser.parse_args()

#Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

ipr = Popen(['ip', 'route'], stdout=PIPE, stderr=DN)
ipr = ipr.communicate()[0]
routerRE = re.search('default via ((\d{2,3}\.\d{1,3}\.\d{1,4}\.)\d{1,3}) \w+ (\w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]?)', ipr)
routerIP = routerRE.group(1)
IPprefix = routerRE.group(2)
interface = routerRE.group(3)
localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
localMAC = get_if_hwaddr(interface)
IPandMAC = []
wired = 0
new_clients = []
start_time = time.time()
current_time = 0

print '[+] Running arp scan'
ans,unans = arping(IPprefix+'*', timeout=5)
for s,r in ans:
	hw = r[ARP].hwsrc
	ip = r[ARP].psrc
	IPandMAC.append([hw, ip, 0, 0, 0, 0]) # data, req2send, clear2send, ack or block ack

t = 0
for x in IPandMAC:
	if routerIP in x[1]:
		routerMAC = x[0]
		t = 1
		break
if t == 0:
	sys.exit('Router MAC not found')

#Do nbtscan for windows netbios names
print '[+] Running nbtscan'
try:
	nbt = Popen(['nbtscan', IPprefix+'0/24'], stdout=PIPE, stderr=DN)
	nbt = nbt.communicate()[0]
	nbt = nbt.splitlines()
except:
	print '[-] nbtscan error, are you sure it is installed?'
if len(nbt) < 5:
	print '[-] nbtscan failed'
for l in nbt:
	if l.startswith(IPprefix):
		ip_name = re.search('(\d{2,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\w+)', l)
		try:
			nbtip = ip_name.group(1)
		except:
			continue
		try:
			netbios = ip_name.group(2)
		except:
			continue
		for a in IPandMAC:
			if nbtip and netbios:
				if 'Sendto' not in netbios:
					if nbtip in a:
						a.append(netbios)

#Start monitor mode
print '\n[+] Enabling monitor mode'
try:
	promisc = Popen(['airmon-ng', 'start', '%s' % interface], stdout=PIPE, stderr=DN)
	promisc = promisc.communicate()[0]
	monmode = re.search('monitor mode enabled on (.+)\)', promisc)
	monmode = monmode.group(1)
except OSError, e:
	sys.exit('[-] Enabling monitor mode failed, do you have aircrack-ng installed?')

def newclients(pkt):
	global IPandMAC
	newIP = ''
	newMAC = ''
	if pkt.haslayer(DHCP):
		#Check for message-type == 3 which is the second request the client makes
		if pkt[DHCP].options[0][1] == 3:
			opt = pkt[DHCP].options
			for x in opt:
				if "requested_addr" in repr(x):
					newIP = x[1]
					newMAC = pkt[Ether].src
					if newIP != '' and newMAC != '':
						tstamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
						new_clients.append('[%s] %s at %s joined the network' % (tstamp, newMAC, newIP))
						for y in IPandMAC:
							if newIP == y[1]:
								return
					IPandMAC.append([newMAC, newIP, 0, 0, 0, 0, 0])
	if pkt.haslayer(ARP):
		if pkt[ARP].op == 2:
			for x in IPandMAC:
				if pkt[ARP].hwsrc == x[0]:
					return
				newIP = pkt[ARP].psrc
				newMAC = pkt[ARP].hwsrc
			IPandMAC.append([newMAC, newIP, 0, 0, 0, 0, 0])
			new_clients.append("Added %s to list due to arp is-at, may've not been caught by initial arp scan" % newIP)

class newDevices(threading.Thread):
	def run(self):
		sniff(store=0, filter='port 67 or 68', prn=newclients, iface=interface)

nd = newDevices()
nd.daemon = True
nd.start()

def main(pkt):
	global start_time, current_time

	#type 2 is Data, type 0 is Management which is auth/deauth stuff, type 1 is control which is ACKs, request to sent, clear to send stuff
	if pkt.haslayer(Dot11):
		pkt = pkt[Dot11]
		if pkt.type in [1,2]:
			dstMAC = pkt.addr1
			srcMAC = pkt.addr2 # usually the router
			srcMAC2 = pkt.addr3 # if it's comp1 > router > comp2 then this is comp1
			if localMAC in [dstMAC, srcMAC, srcMAC2]:
				return
			ptype = pkt.type
			subtype = pkt.subtype
			for x in IPandMAC:
				if srcMAC == x[0] or dstMAC == x[0] or srcMAC2 == x[0]:
					if ptype == 1: # control
						if subtype == 9 or subtype == 13: # block acknowledgement or acknowledgement
							x[5] = x[5]+1
						elif subtype == 11: # request to send
							x[3] = x[3]+1
						elif subtype == 12: # clear to send
							x[4] = x[4]+1
					elif ptype == 2: # data
						x[2] = x[2]+1
			current_time = time.time()
			if current_time > start_time+1:
				IPandMAC.sort(key=lambda x: float(x[2]), reverse=True) # sort by data packets
				os.system('clear')
				print '               '+GR+'%d'%len(IPandMAC)+W+' clients                '+R+'Data        '+G+'Control Frame'+W
				print '           MAC             IP                    '+G+' Req   Clear    Acks '+W
				for x in IPandMAC:
					if x[2] != 0 or x[3] != 0 or x[4] != 0 or x[5] != 0:
						if routerIP in x:
							print '[+] %s %-15s'%(x[0],x[1])+R+' %7d'%x[2]+G+' %7d %7d %7d' % (x[3], x[4], x[5])+GR+' (router)'+W
						elif len(x) == 7:
							print '[+] %s %-15s'%(x[0],x[1])+R+' %7d'%x[2]+G+' %7d %7d %7d' % (x[3], x[4], x[5])+W+' %s' % x[6]
						else:
							print '[+] %s %-15s'%(x[0],x[1])+R+' %7d'%x[2]+G+' %7d %7d %7d' % (x[3], x[4], x[5])+ W
				print ''
				if args.join:
					for x in new_clients:
						print x
				start_time = time.time()

		def signal_handler(signal, frame):
			print 'leaning up...'
			Popen(['airmon-ng', 'stop', '%s' % monmode], stdout=PIPE, stderr=DN)
			#arp tables seem to get messed up when starting and stopping monitor mode so this heals the arp tables
			print 'Restoring arp table...'
			Popen(['arp', '-s', routerIP, routerMAC], stdout=PIPE, stderr=DN)
			sys.exit(0)
		signal.signal(signal.SIGINT, signal_handler)

try:
	sniff(iface=monmode, prn=main, store=0)
except socket.error, (value, message):
	print message
except:
	raise

