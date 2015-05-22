#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, WarningAlert, MacAddress
from canari.maltego.message import Label, Field
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
    label='L4 - Find ARP Spoofing [SmP]',
    description='Looks for traffic that might be due to ARP Spoofing',
    uuids=[ 'sniffMyPackets.v2.huntfor_arpspoof' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pkts = rdpcap(request.value)
    unique_macs = []
    mac_list = []

    for p in pkts:
        if p.haslayer(ARP):
            mac = p.getlayer(ARP).hwsrc
            if mac not in unique_macs:
                unique_macs.append(mac)
            mac_list.append(mac)

    counter = 0
    for y in mac_list:
        for x in unique_macs:
            if y in x:
                src = x
                counter += x.count(x[1])
        print str(counter) + ' ' + str(src)

    # for s in unique_macs:
    #     print s

    return response