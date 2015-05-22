#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.ipaddrchanges import *
from canari.maltego.message import Field, MatchingRule
from common.entities import Interface
from canari.maltego.entities import IPv4Address
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
    label='L9 - Local ARP Scan [SmP]',
    description='Run a local arp scan from your interface',
    uuids=[ 'sniffMyPackets.v2.local_arp_scan' ],
    inputs=[ ( 'sniffMyPackets', Interface ) ],
    debug=True
)
def dotransform(request, response):

    interface = request.value

    conf.iface=interface
    subnet = ''
    network = ''
    cidr = ''
    arpscan = []
    
    for x in conf.route.routes:
      if x[3] == interface and x[2] == '0.0.0.0':
        subnet = x[1]
        network = x[0]
    
    subnet = subnetAddress(subnet)
    cidr = cidr2subnet(subnet)
    network = networkAddress(network)
        
    ans,uans = arping(str(network)+'/'+str(cidr), verbose=0)
    for send,rcv in ans:
      e = IPv4Address(rcv.sprintf("%ARP.psrc%"))
      e.internal = True
      e += Field('ethernet.hwaddr', rcv.sprintf("%Ether.src%"), displayname='Hardware Address')
      response += e
    return response
