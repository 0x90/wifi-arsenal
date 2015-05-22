#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, WarningAlert
from canari.maltego.message import Label, Field, UIMessage
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
    label='L4 - Look for Suspicious ICMP Payloads [SmP]',
    description='Looks through pcap and tries to identify ICMP tunnels',
    uuids=[ 'sniffMyPackets.v2.pcap_2_icmptunnel' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):

    pcap = request.value
    pkts = rdpcap(pcap)
    folder = request.fields['sniffMyPackets.outputfld']
    output_file = folder + '/suspicious-icmp.pcap'

    icmp_packets = []
    # Common ICMP payload types for ping
    icmp_payload = ['0123567', 'abcdef']
    suspicious = 0

    # Look for ICMP request and reply packets and store in new list
    for p in pkts:
        if p.haslayer(IP) and p.haslayer(ICMP):
            if p[ICMP].type == 8:
                icmp_packets.append(p)
            if p[ICMP].type == 0:
                icmp_packets.append(p)

    # Look through ICMP packets stored in list and check the payload against common ping payloads
    for x in icmp_packets:
        if x.haslayer(Raw):
            for s in icmp_payload:
                load = str(x[Raw].load)
                if s not in load:
                    suspicious = 1

    # Write files out to a new pcap
    wrpcap(output_file, icmp_packets)

    # If there is something dodgy write it out to Maltego otherwise return message to UI
    if suspicious == 1:
        e = WarningAlert('Suspicious ICMP Payload')
        e.linklabel = 'Output ' + output_file
        e += Field('sniffMyPackets.outputfld', folder, displayname='Folder Location')
        e += Field('dumpfile', output_file, displayname='Output File', matchingrule='loose')
        e.linkcolor = 0xFF0000
        response += e
        return response
    else:
        return response + UIMessage('Nothing dodgy here')