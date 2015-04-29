#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import MacAddress
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field, UIMessage
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
    label='L2 - Extract IPv4 from MAC [SmP]',
    description='Pulls out IPv4 Addresses that match the MAC address',
    uuids=[ 'sniffMyPackets.v2.macaddr_2_ip' ],
    inputs=[ ( 'sniffMyPackets', MacAddress ) ],
    debug=False
)
def dotransform(request, response):

    s_mac = request.value
    ip_list = []
    pcap = request.fields['pcapsrc']

    pkts = rdpcap(pcap)

    for x in pkts:
        if x.haslayer(IP):
            if s_mac == x[Ether].src:
                s_ip = x[IP].src
                if s_ip not in ip_list:
                    ip_list.append(s_ip)

    for t in ip_list:
        e = IPv4Address(t)
        e += Field('pcapsrc', pcap, displayname='Original pcap File')
        response += e
    return response
