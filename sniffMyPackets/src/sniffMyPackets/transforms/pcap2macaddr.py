#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, MacAddress
from canari.maltego.message import Field
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
    label='L2 - Extract MAC Addresses [SmP]',
    description='Extracts all MAC addresses from a pcap file',
    uuids=[ 'sniffMyPackets.v2.pcap_2_macaddr' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):

    pcap = request.value
    mac_list = []

    pkts = rdpcap(pcap)

    for x in pkts:
        if x.haslayer(Ether):
            s_mac = x[Ether].src
            if s_mac not in mac_list:
                mac_list.append(s_mac)

    for m in mac_list:
        e = MacAddress(m)
        e += Field('pcapsrc', pcap, displayname='Original pcap File')
        response += e
    return response
