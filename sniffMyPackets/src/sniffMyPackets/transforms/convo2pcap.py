#!/usr/bin/env python

import logging, os, hashlib, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, Host
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
    label='L2 - Write Convo [SmP]',
    description='Takes a TCP/UDP convo and saves out to pcap file',
    uuids=[ 'sniffMyPackets.v2.TCPConvo2pcapfile' ],
    inputs=[ ( 'sniffMyPackets', Host ) ],
    debug=True
)
def dotransform(request, response):
	
    pcap = request.fields['pcapsrc']
    proto = request.fields['proto']
    dstip = request.fields['sniffMyPackets.hostdst']
    srcip = request.fields['sniffMyPackets.hostsrc']
    sport = request.fields['sniffMyPackets.hostsport']
    dport = request.fields['sniffMyPackets.hostdport']
    folder = request.fields['sniffMyPackets.outputfld']
    filename = folder + '/' + str(request.value) + '-' + str(srcip) + '.pcap'
   
    # Filter the traffic based on the entity values and save the pcap file with new name
    sharkit = 'tcpdump -r ' + pcap + ' host ' + srcip + ' and port ' + sport + ' -w ' + filename
    os.system(sharkit)

    # Count the number of packets in the file
    pktcount = ''
    pkts = rdpcap(filename)
    pktcount = len(pkts)
    
    # Hash the file and return a SHA1 sum
    sha1sum = ''
    fh = open(filename, 'rb')
    sha1sum = hashlib.sha1(fh.read()).hexdigest()
    
    e = pcapFile(filename)
    e.sha1hash = sha1sum
    e += Field('pktcnt', pktcount, displayname='Number of packets', matchingrule='loose')
    e.linklabel = '# of pkts:' + str(pktcount)
    e.linkcolor = 0x669900
    response += e
    return response