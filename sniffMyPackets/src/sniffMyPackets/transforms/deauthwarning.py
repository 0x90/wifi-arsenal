#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, WarningAlert
from canari.maltego.message import Label
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
    label='L4 - Find DeAuth Attack [SmP]',
    description='Looks for large numbers of Deauth Packets',
    uuids=[ 'sniffMyPackets.v2.Findwifi_deatuhattack' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
  pkts = rdpcap(request.value)
  deauth_packets = []
  station = []
  
  for p in pkts:
	if p.haslayer(Dot11) and p.haslayer(Dot11Deauth):
	  deauth_packets.append(p.getlayer(Dot11).addr2)
	  if p.getlayer(Dot11).addr2 not in station:
	    station.append(p.getlayer(Dot11).addr2)
	    
  
  for x in station:
    e = WarningAlert('Deauth Attack:' + str(x))
    e.linklabel = '# of pkts: ' + str(deauth_packets.count(x))
    e.linkcolor = 0xFF0000
    response += e
  return response