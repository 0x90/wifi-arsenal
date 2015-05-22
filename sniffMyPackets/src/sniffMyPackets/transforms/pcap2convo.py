#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, Host
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field, Label, MatchingRule
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]



#@superuser
@configure(
    label='L2 - Find TCP/UDP Convo [SmP]',
    description='Maps TCP/UDP Conversations',
    uuids=[ 'sniffMyPackets.v2.pcap2TCPConvo' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=False
)
def dotransform(request, response):
    
  convo = []
  target = request.value
  pcap = request.fields['pcapsrc']
  pkts = rdpcap(pcap)
  
  for p in pkts:
		if p.haslayer(TCP) and p.getlayer(IP).src == target:
			srcip = p.getlayer(IP).src
			dstip = p.getlayer(IP).dst
			sport = p.getlayer(TCP).sport
			dport = p.getlayer(TCP).dport
			talker = srcip, dstip, sport, dport, pcap, 'tcp'
			if talker not in convo:
				convo.append(talker)

		if p.haslayer(IP) and p.haslayer(UDP) and p.getlayer(IP).src == target:
			srcip = p.getlayer(IP).src
			dstip = p.getlayer(IP).dst
			sport = p.getlayer(UDP).sport
			dport = p.getlayer(UDP).dport
			talker = srcip, dstip, sport, dport, pcap, 'udp'
			if talker not in convo:
				convo.append(talker)
  
  for src, dst, sport, dport, pcap, proto in convo:
	  e = Host(dst)
	  e.hostsrc = src
	  e.hostdst = dst
	  e.hostsport = sport
	  e.hostdport = dport
	  e.linklabel = proto + '\n' + str(sport) + ':' + str(dport)
	  if proto == 'tcp':
		e.linkcolor = 0x2314CA
	  if proto == 'udp':
		e.linkcolor = 0x0E7323
	  e += Field('pcapsrc', pcap, displayname='Original pcap File')
	  e += Field('proto', proto, displayname='Protocol')
	  response += e
  return response

