#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import Website
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
    label='L4 - Check HTTP Hosts [SmP]',
    description='Read a pcap file and return list of Hosts from GET requests',
    uuids=[ 'sniffMyPackets.v2.httpgetrequests2domain' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
    
    pcap = request.value
    get_requests = []
    
    cmd = 'tshark -r ' + pcap + ' -R "http.request.method == GET" -T fields -e http.host'
    a = os.popen(cmd).readlines()
    
    for host in a:
	  if host not in get_requests:
		get_requests.append(host)
   
    for host in get_requests:
      e = Website(host)
      response += e
    return response
