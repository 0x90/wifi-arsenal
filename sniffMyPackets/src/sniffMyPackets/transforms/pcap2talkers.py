#!/usr/bin/env python

import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field, Label
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
    label='L2 - Find TCP/UDP Talkers [SmP]',
    description='Search a pcap file and return all TCP/UDP',
    uuids=[ 'sniffMyPackets.v2.pcap2talkers' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
  
  pcap = request.value
  pkts = rdpcap(pcap)
  tcp_srcip = []
  udp_srcip = []
  convo = []

  for p in pkts:
    if p.haslayer(TCP):
      tcp_srcip.append(p.getlayer(IP).src)
    if p.haslayer(IP) and p.haslayer(UDP):
      udp_srcip.append(p.getlayer(IP).src)

  for x in tcp_srcip:
    talker = x, str(tcp_srcip.count(x)), 'tcp'
    if talker not in convo:
      convo.append(talker)

  for y in udp_srcip:
    talker = y, str(udp_srcip.count(y)), 'udp'
    if talker not in convo:
      convo.append(talker)

  for srcip, count, proto in convo:
    e = IPv4Address(srcip)
    e.linkcolor = 0x2314CA
    e.linklabel = proto
    e += Field('pcapsrc', pcap, displayname='Original pcap File')
    e += Field('proto', proto, displayname='Protocol')
    response += e
  return response

