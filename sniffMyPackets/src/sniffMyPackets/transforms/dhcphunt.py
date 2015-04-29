#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, DHCPServer
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
    'dotransform',
    'onterminate'
]



#@superuser
@configure(
    label='L4 - Find DHCP Servers [SmP]',
    description='Reads pcap file and returns DHCP servers and options',
    uuids=[ 'sniffMyPackets.v2.pcap2dhcpserver' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  # Load the pcap file and store as pkts
  pkts = rdpcap(request.value)
  
  # Create empty list to store the output from the raw DHCP packetsl
  dhcp_raw = []
  
  # Parse through the packets looking only for BOOTP replies with op=0x02 (BOOTP Reply) and BOOTP ACK
  for x in pkts:
	if x.haslayer(BOOTP) and x.haslayer(DHCP) and x.getlayer(BOOTP).op == 0x02:
	  raw = x.getlayer(DHCP).options
	  if 0x05 in raw[0]:
		for line in raw:
		  dhcp_raw.append(line)
  
  if len(dhcp_raw) != 0:
    x =  '\n'.join(map(str, dhcp_raw))
    
    
    serverid = ''
    subnet = ''
    lease = ''
    gateway = ''
    domain = str('')
    dnsserver = ''
    for s in re.finditer('(\'server_id\'\, \')(\d*.\d*.\d*.\d*)', x):
      serverid = s.group(2)
    for s in re.finditer('(\'subnet_mask\'\, \')(\d*.\d*.\d*.\d*)', x):
     subnet = s.group(2)
    for s in re.finditer('(\'router\'\, \')(\d*.\d*.\d*.\d*)', x):
     gateway = s.group(2)
    for s in re.finditer('(\'name_server\'\, \')(\d*.\d*.\d*.\d*)', x):
     dnsserver = s.group(2)
    for s in re.finditer('(\'lease_time\'\, )(\d*)', x):
     lease = s.group(2)
    for s in re.finditer('(\'domain\'\, )(\S*)', x):
     domain = s.group(2)[1:-6]
    
    e = DHCPServer(serverid)
    e.dhcpsubnet = subnet
    e.linklabel = lease
    e.dhcpns = dnsserver
    e.dhcpgw = gateway
    e.dhcpdomain = domain
    response += e
    return response
  else:
    return response + UIMessage('No DHCP Servers found!!')