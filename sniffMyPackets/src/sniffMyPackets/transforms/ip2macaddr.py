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
    label='L4 - IP address to MAC address [SmP]',
    description='Returns MAC address from IPv4 Address',
    uuids=[ 'sniffMyPackets.v2.IPAddr_2_MACaddr' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=False
)
def dotransform(request, response):
    
    s_ip = request.value
    layers = ['IP', 'ARP']
    try:
        pcap = request.fields['pcapsrc']
    except:
        return response + UIMessage('Sorry this isnt a SmP IP Address')
    
    mac_list = []
    pkts = rdpcap(pcap)

    for x in pkts:
        for s in layers:
            if x.haslayer(s) and s == 'ARP':
                if x[ARP].psrc == s_ip:
                    mac = x[Ether].src
                    if mac not in mac_list:
                        mac_list.append(mac)
            if x.haslayer(s) and s == 'IP':
                if x[IP].src == s_ip:
                    mac = x[Ether].src
                    if mac not in mac_list:
                        mac_list.append(mac)

    for x in mac_list:
        e = MacAddress(x)
        e += Field('pcapsrc', pcap, displayname='Original pcap File')
        e += Field('ipaddrsrc', s_ip, displayname='Original IP Address')
        response += e
    return response
