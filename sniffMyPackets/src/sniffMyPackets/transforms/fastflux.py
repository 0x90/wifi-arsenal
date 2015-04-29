#!/usr/bin/env python

import os, sys, re
import logging, os, glob, uuid, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, WarningAlert
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
    label='L4 - Check for FastFlux [SmP]',
    description='Checks a pcap file and looks for fastflux domains',
    uuids=[ 'sniffMyPackets.v2.check4fastflux' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
	
  pcap = request.value
  pkts = rdpcap(pcap)
  dnsHost = []
  
  for x in pkts:
    if x.haslayer(DNS) and x.haslayer(DNSRR):
      ancount = x.getlayer(DNS).ancount
      qname = x.getlayer(DNSRR).rrname
      ttl = x.getlayer(DNSRR).ttl
      if ancount >= 7 or ttl == 0:
        dnsrec = qname, ancount, ttl
        if dnsrec not in dnsHost:
          dnsHost.append(dnsrec)
  
  
  for dnsv, dnsc, ttl in dnsHost:
      e = WarningAlert('Fast Flux?: ' + dnsv)
      e.linklabel = 'Unique IPs: ' + str(dnsc)
      e += Field('dnsttl', ttl, displayname='TTL')
      e.linkcolor = 0xFF0000
      response += e
  return response