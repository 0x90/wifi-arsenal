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
    label='L4 - Find TCP Port Scan [SmP]',
    description='Looks through pcap file and identities possible port scan attacks',
    uuids=[ 'sniffMyPackets.v2.findSYNattacks' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  tcpflags = {'SYN': 02, 'FIN': 0x001, 'XMAS': 0x029, 'ACK': 0x010, 'NULL': 0x000}
  senders = []
  talkers = []
 

  for p in pkts:
    for key, value in tcpflags.iteritems():
      if p.haslayer(TCP) and p.getlayer(TCP).flags == int(value):
        dport = p.getlayer(TCP).dport
        srcip = p.getlayer(IP).src
        flagset = key
        talker = srcip, dport, flagset
        if talker not in talkers:
          talkers.append(talker)
        if srcip not in senders:
          senders.append(srcip)
  
  counter = 0
  for x in senders:
    for y in talkers:
      if x in y:
        src = y[0]
        counter += y.count(y[1])
        flag = y[2]
        e = WarningAlert(str(flag) + ' scan from: ' + str(src))
        e.linklabel = '# of connections: ' + str(counter)
        e.linkcolor = 0xFF0000
        response += e
      return response