#!/usr/bin/env python

import logging, os, sys, re
from subprocess import Popen
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from canari.maltego.entities import Domain, IPv4Address
from canari.maltego.message import UIMessage, Field, Label
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
    label='L3 - Map DNS request to Server IP [SmP]',
    description='Maps a DNS response made by client back to the server IP',
    uuids=[ 'sniffMyPackets.v2.dnsrequest_2_server' ],
    inputs=[ ( 'sniffMyPackets', Domain ) ],
    debug=False
)
def dotransform(request, response):
    
    domain = request.value
    pcap = request.fields['pcapsrc']
    ans_ip = []
    rec_count = ''

    pkts = rdpcap(pcap)

    for p in pkts:
        if p.haslayer(DNS) and p.haslayer(DNSQR):
            if domain == p[DNSQR].qname:
                rec_count = p[DNS].ancount

    # print rec_count

    if rec_count > 1:
        domain = domain.strip('.')
        cmd = 'tshark -r ' + pcap + ' -R "dns.qry.name == ' + domain + ' && dns.flags.response == 1" -V'
        # print cmd
        a = os.popen(cmd).readlines()
        for s in re.finditer('Addr: (\d*.\d*.\d*.\d*)', str(a)):
            x = s.group(1)
            if x not in ans_ip:
                ans_ip.append(x)
    else:
        for p in pkts:
            if p.haslayer(DNS) and p.haslayer(DNSRR):
                ip = p[DNSRR].rdata
                if ip not in ans_ip:
                    ans_ip.append(ip)

    
    for dip in ans_ip:
        e = IPv4Address(dip)
        e += Field('pcapsrc', pcap, displayname='Original pcap File')
        e.linklabel = 'Server'
        response += e

    return response
