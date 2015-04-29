#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Label, Field
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
    label='L4 - Find ARP packets [SmP]',
    description='Looks through a pcap file and returns IPs from ARP requests',
    uuids=[ 'sniffMyPackets.v2.readarppackets' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  hosts = []
  
  for p in pkts:
    if p.haslayer(ARP):
      e_src = p[ARP].psrc
      i_src = p[Ether].src
      host = i_src, e_src
      if host not in hosts:
        hosts.append(host)

  for mac, ip in hosts:
    e = IPv4Address(ip)
    e.linklabel = 'ARP'
    e += Field('pcapsrc', request.value, displayname='Original pcap File')
    e += Field('macaddrsrc', mac, displayname='MAC Address')
    response += e
  return response
