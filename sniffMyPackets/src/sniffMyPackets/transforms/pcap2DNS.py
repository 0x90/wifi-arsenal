#!/usr/bin/env python


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.message import UIMessage, Field
from canari.maltego.entities import Domain
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
    label='L3 - Find DNS Queries [SmP]',
    description='Reads a pcap file looks for DNS queries',
    uuids=[ 'sniffmyPackets.v2.pcapFiletoDNS' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
  
	dns_results = []
	
	pcap = request.value
	pkt = rdpcap(pcap)
	
	for pkts in pkt:
	  if pkts.haslayer(DNSQR):
		drec = pkts.getlayer(DNSQR).qname
		if drec not in dns_results:
		  dns_results.append(drec)
	
	for drec in dns_results:
		e = Domain(drec.strip('.'))
		e += Field('pcapsrc', pcap, displayname='Original pcap File')
		response += e
	return response  
