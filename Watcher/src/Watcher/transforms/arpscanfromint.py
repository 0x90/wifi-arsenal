#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.ipaddrchanges import *
from canari.framework import configure #, superuser
from common.entities import Interface
from canari.maltego.message import Field
from canari.maltego.entities import IPv4Address

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Watcher Project'
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
    label='Watcher - ARP scan',
    description='Performs an arp scan to determine devices on network',
    uuids=[ 'Watcher.v2.arp_scan_from_interface' ],
    inputs=[ ( 'Watcher', Interface ) ],
    debug=True
)
def dotransform(request, response):
    
    iface = request.value
    conf.iface = iface
    subnet = ''
    network = ''

    for x in conf.route.routes:
        if x[3] == iface and x[2] == '0.0.0.0':
            subnet = x[1]
            network = x[0]

    subnet = subnetAddress(subnet)
    cidr = cidr2subnet(subnet)
    network = networkAddress(network)

    ans, uans = arping(network + '/' + str(cidr), verbose=0)
    for send, rcv in ans:
        e = IPv4Address(rcv[ARP].psrc)
        e += Field('ethernet.hwaddr', rcv[Ether].src, displayname='Hardware Address')
        e.internal = True
        response += e
    return response
