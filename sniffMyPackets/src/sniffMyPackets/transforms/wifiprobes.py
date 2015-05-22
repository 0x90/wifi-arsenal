#!/usr/bin/env python


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, WifiClient
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
    label='L4 - Find Wireless Probes [SmP]',
    description='Looks for Wifi Probes and maps to client',
    uuids=[ 'sniffMyPackets.v2.pcapfindwifiprobes' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  clients = []
  
  for p in pkts:
	if p.haslayer(Dot11ProbeReq):
	  mac = p.getlayer(Dot11).addr2
	  ssid = p.getlayer(Dot11Elt).info
	  ssid=ssid.decode('utf-8','ignore')
	  if ssid == "":
		ssid="<BROADCAST>" 
	  station = mac, ssid
	  if station not in clients:
		clients.append(station)

  for mac, ssid in clients:
	e = WifiClient(mac)
	e.clientSSID = ssid
	e.linklabel = ssid
	e.linkcolor = 0xFF00FF
	response += e
  return response