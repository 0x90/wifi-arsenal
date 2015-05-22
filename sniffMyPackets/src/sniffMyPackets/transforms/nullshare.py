#!/usr/bin/env python

import os, logging, re
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
    label='L4 - Find Null Share Connections [SmP]',
    description='Looks for attackers mapping null share',
    uuids=[ 'sniffMyPackets.v2.pcap2null_shares' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    pkts = rdpcap(request.value)
    ips = []
    success = 'SMBu\\x00\\x00\\x00\\x00'
    null_share = 'IPC$'

    for p in pkts:
        if p.haslayer(TCP) and p.getlayer(TCP).dport == 445 and p.haslayer(Raw):
            raw = p.getlayer(Raw).load
            srcip = p.getlayer(IP).src
            dstip = p.getlayer(IP).dst
            if success and null_share in raw:
                convo = srcip, dstip
                if convo not in ips:
                    ips.append(convo)


    for src, dst in ips:
        e = WarningAlert('Null Share:\n' + str(src) + '->' + str(dst))
        e.linklabel = str(null_share)
        e.linkcolor = 0xFF0000
        response += e
    return response
