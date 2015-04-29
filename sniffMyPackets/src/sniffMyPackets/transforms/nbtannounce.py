#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field, Label
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
    label='L4 - Find NBT Announcements [SmP]',
    description='Reads a pcap file and looks for NBT Announcements',
    uuids=[ 'sniffMyPackets.v2.findnbtannouncements' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):

    pkts = rdpcap(request.value)
    nbt_hosts = []

    for p in pkts:
        if p.haslayer(UDP) and p.haslayer(NBTDatagram) and p.getlayer(UDP).sport == 138:
            s_ip = p.getlayer(NBTDatagram).SourceIP
            s_name = p.getlayer(NBTDatagram).SourceName
            d_name = p.getlayer(NBTDatagram).DestinationName
            nhost = s_ip, s_name, d_name
            if nhost not in nbt_hosts:
                nbt_hosts.append(nhost)

    for ip, name, dname in nbt_hosts:
        e = IPv4Address(ip)
        e.linkcolor = 0xCC66FF
        e.linklabel = name
        e += Field('pcapsrc', request.value, displayname='Original pcap File')
        e += Field('dname', dname, displayname='Domain Name')
        response += e
    return response
