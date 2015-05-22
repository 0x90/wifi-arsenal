#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, AppleTV
from canari.maltego.message import Field
#from canari.maltego.utils import debug, progress
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
    label='L4 - Find AppleTV Devices [SmP]',
    description='Looks through pcap file for AppleTV devices and checks for password protection',
    uuids=[ 'sniffMyPackets.v2.pcapfile2appletv' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
  pkts = rdpcap(request.value)
  passwd = 'True'
  model = ''
  hwaddr = ''
  srcip = ''
  name = ''
  raw_mdns = []
  
  for pkt in pkts:
    if pkt.haslayer(UDP) and pkt.getlayer(UDP).sport == 5353:
      raw = pkt.getlayer(Raw).load
      srcip = pkt.getlayer(IP).src
      hwaddr = pkt.getlayer(Ether).src
      if raw not in raw_mdns:
	raw_mdns.append(raw)
	  
  for x in raw_mdns:
    for s in re.finditer('pw=false', x):
      if s is not None:
	passwd = 'False'
      else:
	passwd = 'True'
    for s in re.finditer('model=(\w*?!)', x):
      if s is not None:
	model = s.group(1)
    for s in re.finditer('Name=(.*)', x):
      if s is not None:
	name = s.group(1)
      
  appletv = 'Name:' + name + '\npwd:' + passwd
  e = AppleTV(appletv)
  e += Field('appleip', srcip, displayname='AppleTV IP', matchingrule='loose')
  e += Field('applemac', hwaddr, displayname='AppleTV MAC', matchingrule='loose')
  response += e
  return response