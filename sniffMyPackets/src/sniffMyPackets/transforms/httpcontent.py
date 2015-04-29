#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, FileDump
from canari.maltego.message import Field, Label
#from canari.maltego.utils import debug, progress
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
    label='L4 - Check HTTP Content [SmP]',
    description='Checks pcap for HTTP content types',
    uuids=[ 'sniffMyPackets.v2.pullHTTPcontent' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pkts = rdpcap(request.value)
    content_type = []
    ctype = ''
    dstip = ''
    srcport = ''
    clength = ''
    
    for x in pkts:
	  if x.haslayer(TCP) and x.haslayer(Raw):
		raw = x.getlayer(Raw).load
		dstip = x.getlayer(IP).src
		srcport = x.getlayer(TCP).dport
		for s in re.finditer('Content-Type:*\S*\D\S*', raw):
		  if s is not None:
			ctype = s.group()
		  for t in re.finditer('Content-Length:*\S*\D\S*', raw):
		    if t is not None:
			clength = t.group()
		    content = ctype, dstip, srcport, clength
		    if content not in content_type:
			content_type.append(content)
	
    for ctype, cip, cport, clength in content_type:
	  e = FileDump(ctype)
	  e.cip = cip
	  e.cport = cport
	  e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
	  e.linklabel = clength
	  e.linkcolor = 0x33CC33
	  response += e
    return response
	  
	
    
