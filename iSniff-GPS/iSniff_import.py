#!/usr/bin/python

from color import *
from netaddr import EUI
from scapy.all import *
from dnslib import DNSRecord # for mdns/bonjour name parsing
from django.utils import timezone
from django.core.exceptions import *
from datetime import datetime #for utcfromtimestamp
from iSniff_GPS.models import Client, AP, Location
from collections import defaultdict

import code
import binascii
import argparse
import json
import sys
import re

parser = argparse.ArgumentParser(description='iSniff GPS Server')
parser.add_argument('-r', dest='pcap', action='store', help='pcap file to read')
parser.add_argument('-i', dest='interface', action='store', default='mon0', help='interface to sniff (default mon0)')
args = parser.parse_args()

count = 0 #count of scapy packets processed
client = defaultdict(list)
interface = "mon0"

def ascii_printable(s):
	return ''.join(i for i in s if ord(i)>31 and ord(i)<128)

def get_manuf(m):
	try:
		mac = EUI(m)
		manuf = mac.oui.records[0]['org'].split(' ')[0].replace(',','')
		#.replace(', Inc','').replace(' Inc.','')
	except:
		manuf='unknown'
	return ascii_printable(manuf)

def CreateOrUpdateClient(mac,utc,name=None):
	try:
		c = Client.objects.get(mac=mac)
		if c.lastseen_date < utc:
			c.lastseen_date = utc
		#print 'Updated time on object %s' % mac
	except ObjectDoesNotExist:
		c = Client(mac=mac, lastseen_date=utc, manufacturer=get_manuf(mac))
		#print 'Created new object %s' % mac
	if name:
		c.name = name
		print 'Updated name of %s to %s' % (c,c.name)
	c.save()
	return c

def UpdateDB(clientmac=None,time=None,SSID='',BSSID=''):
	utc = datetime.utcfromtimestamp(time)
	if SSID:
		try:
			a = AP.objects.get(SSID=SSID)
		except ObjectDoesNotExist:
			a = AP(SSID=SSID, lastprobed_date=utc, manufacturer='Unknown')
	elif BSSID:
		try:
			a = AP.objects.get(BSSID=BSSID)
		except ObjectDoesNotExist:
			a = AP(BSSID=BSSID, lastprobed_date=utc, manufacturer=get_manuf(BSSID))
	if a.lastprobed_date and a.lastprobed_date < utc:
		a.lastprobed_date = utc
	a.save() #avoid ValueError: 'AP' instance needs to have a primary key value before a many-to-many relationship can be used.
	a.client.add(CreateOrUpdateClient(clientmac,utc))
	a.save()

def process(p):
	global count 
	count += 1
	if count % 10000 == 0:
		print count

	if p.haslayer(ARP):
		arp = p.getlayer(ARP)
		dot11 = p.getlayer(Dot11)
		mode = ''
		try:
			target_bssid = dot11.addr1 # on wifi, BSSID (mac) of AP currently connected to
			source_mac = dot11.addr2 # wifi client mac
			target_mac = dot11.addr3 # if we're sniffing wifi (mon0) the other-AP bssid disclosure will be here in 802.11 dest
			if dot11.FCfield == 1 and target_bssid != 'ff:ff:ff:ff:ff:ff' and arp.op == 1 and target_mac != 'ff:ff:ff:ff:ff:ff' and source_mac != target_mac:
				print ('%s [%s] '+great_success('ARP')+' who has %s? tell %s -> %s [%s] on BSSID %s') % \
				(get_manuf(source_mac),source_mac,arp.pdst,arp.psrc,get_manuf(target_mac),target_mac,target_bssid)
				UpdateDB(clientmac=source_mac, time=p.time, BSSID=target_mac)
				#code.interact(local=locals())

		except:
			try:
				if p.haslayer(Ether):
					source_mac = p.getlayer(Ether).src # wifi client mac when sniffing a tap interface (e.g. at0 provided by airbase-ng)
					target_mac = p.getlayer(Ether).dst # we won't get any 802.11/SSID probes but the bssid disclosure will be in the ethernet dest
					if target_mac != 'ff:ff:ff:ff:ff:ff' and arp.op == 1:
						print ('%s [%s] '+great_success('ARP')+' who has %s? tell %s -> %s [%s] (Ether)') % \
						(get_manuf(source_mac),source_mac,arp.pdst,arp.psrc,get_manuf(target_mac),target_mac)
						UpdateDB(clientmac=source_mac, time=p.time, BSSID=target_mac)
			except IndexError:
				pass

	elif p.haslayer(Dot11ProbeReq):
		mac = p.getlayer(Dot11).addr2
		for p in p:
			if p.haslayer(Dot11Elt) and p.info:
				try:
					probed_ssid = p.info.decode('utf8')
				except UnicodeDecodeError:
					probed_ssid = 'HEX:%s' % binascii.hexlify(p.info)
					print '%s [%s] probed for non-UTF8 SSID (%s bytes, converted to "%s")' % (get_manuf(mac),mac,len(p.info),probed_ssid)
				if len(probed_ssid) > 0 and probed_ssid not in client[mac]:
					client[mac].append(probed_ssid)
					UpdateDB(clientmac=mac, time=p.time, SSID=probed_ssid) #unicode goes in DB for browser display
					return "%s [%s] probe for %s" % (get_manuf(mac),mac,ascii_printable(probed_ssid)) #ascii only for console print

	elif p.haslayer(Dot11AssoReq) or p.haslayer(Dot11AssoResp) or p.haslayer(Dot11ReassoReq) or p.haslayer(Dot11ReassoResp):
		pass
		#print p.summary()
		#print p.fields
		
	if p.haslayer(Dot11) and p.haslayer(UDP) and p.dst == '224.0.0.251':
		for p in p: #only parse MDNS names for 802.11 layer sniffing for now, easy to see what's a request from a client
			if p.dport == 5353:
				try:
					d=DNSRecord.parse(p['Raw.load'])
					for q in d.questions:
						if q.qtype == 255 and '_tcp.local' not in str(q.qname):
							try:
								src=p.getlayer('Dot11').addr3
								name=str(q.qname).strip('.local')
								print great_success('%s is %s') % (src, name)
								#code.interact(local=locals())
								if src != '01:00:5e:00:00:fb':
									CreateOrUpdateClient(src,datetime.utcfromtimestamp(p.time),name)
							except AttributeError:
								print warning('Error parsing MDNS')
				except IndexError:
					pass

if args.pcap:
	print 'Reading %s...' % args.pcap
	sniff(offline=args.pcap, prn=lambda x:process(x), store=0)
else:
	print 'Sniffing %s...' % args.interface
	sniff(iface=args.interface, prn=lambda x:process(x), store=0)

print
print 'Summary'
print '-------'
print

for mac in client:
	print '%s [%s] probed for %s' % (get_manuf(mac),mac,', '.join(map(ascii_printable,client[mac])))

#print json.dumps(client)
