#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import time
from canari.easygui import multenterbox
from common.entities import pcapFile
from canari.maltego.message import Field, Label, UIMessage
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
    label='L0 - Simple pcap search [SmP]',
    description='Simple pcap search function',
    uuids=[ 'sniffMyPackets.v2.search_pcap_file' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    pkts = rdpcap(pcap)
    r_pkts = []

    folder = request.fields['sniffMyPackets.outputfld']
    tstamp = int(time())
    new_file = folder + '/search-results-' + str(tstamp) + '.pcap'

    msg = 'Enter Search Criteria'
    title = 'L0 - Simple pcap search [SmP]'
    fieldNames = ["Source", "Destination", "Port", "Free Text"]
    fieldValues = []
    fieldValues = multenterbox(msg, title, fieldNames)

    s_ip = fieldValues[0]
    if s_ip == '':
        s_ip = None
    d_ip = fieldValues[1]
    if d_ip == '':
        d_ip = None
    port = fieldValues[2]
    if port == '':
        port = None
    text = fieldValues[3]
    if text == '':
        text = None

    if s_ip or d_ip is not None:
        for p in pkts:
            if p.haslayer(IP):
                if p[IP].src == s_ip and not None:
                    r_pkts.append(p)
                if p[IP].dst == d_ip and not None:
                    r_pkts.append(p)

    if port is not None:
        for p in pkts:
            if p.haslayer(TCP):
                if int(port) == p[TCP].sport and not None:
                    r_pkts.append(p)
                if int(port) == p[TCP].dport and not None:
                    r_pkts.append(p)

    if text is not None:
        for p in pkts:
            if p.haslayer(Raw):
                if text in p[Raw].load and not None:
                    r_pkts.append(p)

    if len(r_pkts) > 0:
        wrpcap(new_file, r_pkts)
    else:
        return response + UIMessage('Sorry no packets found!!')

    pktcount = len(r_pkts)

    e = pcapFile(new_file)
    e.outputfld = folder
    e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
    e += Field('pktcnt', pktcount, displayname='Number of packets', matchingrule='loose')
    e.linklabel = 'Search Results'
    response += e
    return response
