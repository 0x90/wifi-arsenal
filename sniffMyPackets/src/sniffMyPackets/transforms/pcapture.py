#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import time
from common.entities import pcapFile, Folder
from canari.framework import configure , superuser

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

@superuser
@configure(
    label='L0 - Capture Packets [SmP]',
    description='Sniffs packets on interface and saves to file',
    uuids=[ 'sniffMyPackets.v2.interface2pcap' ],
    inputs=[ ( 'sniffMyPackets', Folder ) ],
    debug=True
)
def dotransform(request, response):
  
    interface = request.fields['sniffMyPackets.interface']
    tmpfolder = request.value
    tstamp = int(time())
    fileName = tmpfolder + '/' +str(tstamp)+'.pcap' 
    
    if 'sniffMyPackets.count' in request.fields:
      pktcount = int(request.fields['sniffMyPackets.count'])
    else:
      pktcount = 300
    
    pkts = sniff(iface=interface, count=pktcount)
    
    wrpcap(fileName, pkts)
    
    e = pcapFile(fileName)
    e.outputfld = tmpfolder
    response += e
    return response
