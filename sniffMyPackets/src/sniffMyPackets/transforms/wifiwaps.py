#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, AccessPoint
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
    label='L4 - Find Wireless AP [SmP]',
    description='Looks for Beacon frames from Wireless Access Points',
    uuids=[ 'sniffMyPackets.v2.pcap_to_wap' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  aps = []
  
  for p in pkts:
    if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
      ssid = p[Dot11Elt].info
      bssid = p[Dot11].addr3    
      channel = int(ord(p[Dot11Elt:3].info))
      capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
      if re.search("privacy", capability):
	enc = 'Y'
      else: enc  = 'N'

      entity = ssid, bssid, str(channel), enc
      if entity not in aps:
	aps.append(entity)
  
  for ssid, bssid, channel, enc in aps:
    e = AccessPoint(ssid + ':' + bssid)
    e.apbssid = bssid
    e.apchannel = channel
    e.apenc = enc
    e.linklabel = 'Channel:' + channel + '\nEncryption:' + enc
    e.linkcolor = 0xFF4000
    response += e
  return response  