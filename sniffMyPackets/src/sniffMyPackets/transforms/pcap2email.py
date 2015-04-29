#!/usr/bin/env python

import logging, re, uuid, glob
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
from common.dissectors.dissector import *
from common.entities import pcapFile, SMTPEmail
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
    label='L4 - Find SMTP Emails [SmP]',
    description='Read pcap file and look for SMTP emails within',
    uuids=[ 'sniffMyPackets.v2.pcap2smtp' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    pkts = rdpcap(pcap)
    
    tmpfolder = '/tmp/'+str(uuid.uuid4())
    if not os.path.exists(tmpfolder): os.makedirs(tmpfolder)

    streams = []

    smtp_ports = ['25', '587']

    for p in pkts:
        for x in smtp_ports:
            if p.haslayer(TCP) and (p.getlayer(TCP).dport or p.getlayer(TCP).sport == x):
                if p.haslayer(Raw):
                    load = p.getlayer(Raw).load
                    print load
