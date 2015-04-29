#!/usr/bin/env python

import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from canari.easygui import multenterbox
from common.entities import pcapFile
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
    label='L0 - Rewrite pcap file for replay [SmP]',
    description='Rewrites source & destination IP address in a TCP stream',
    uuids=[ 'sniffMyPackets.v2.pcap2rewrite' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    pkts = rdpcap(pcap)

    folder = request.fields['sniffMyPackets.outputfld']
    new_file = folder + '/replay-' + request.value[42:]

    msg = 'Enter the new IPs to rewrite the pcap file with'
    title = 'L0 - Rewrite pcap file for replay [SmP]'
    fieldNames = ["New Source IP", "New Destination IP"]
    fieldValues = []
    fieldValues = multenterbox(msg, title, fieldNames)

    new_src = fieldValues[0]
    new_dst = fieldValues[1]

    old_src = pkts[0][IP].src
    old_dst = pkts[0][IP].dst

    for p in pkts:
        del p[IP].chksum
        del p[TCP].chksum

    for p in pkts:
        if p.haslayer(IP):
            if p[IP].src == old_src:
                p[IP].src = new_src
                p[IP].dst = new_dst
            if p[IP].dst == old_src:
                p[IP].src = new_dst
                p[IP].dst = new_src

    wrpcap(new_file, pkts)
    
    e = pcapFile(new_file)
    e.linklabel = 'New pcap\nsrc:' + str(new_src) + '\ndst:' + str(new_dst)
    e.linkcolor = 0x33CC33
    e.outputfld = folder
    e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
    response += e
    return response
