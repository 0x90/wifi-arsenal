#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, Host
from canari.maltego.message import Label, Field
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
    label='L4 - Find Tor Traffic [SmP]',
    description='Search a pcap file and look for SSL traffic',
    uuids=[ 'sniffMyPackets.v2.pcap2tor_traffic' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  dns_names = []
  tor_traffic = []
  ip_convo = []

  try:
  	tmpfolder = request.fields['sniffMyPackets.outputfld']
  except:
  	pass
  
  
  for x in pkts:
  	if x.haslayer(TCP) and x.haslayer(Raw):
  		if 'www.' in x.getlayer(Raw).load:
  			for s in re.finditer('www.\w*.\w*', str(x)):
  				dnsrec = s.group()
  				srcip = x.getlayer(IP).src
  				dstip = x.getlayer(IP).dst
  				sport = x.getlayer(TCP).sport
  				dport = x.getlayer(TCP).dport
  				ipaddr = srcip, dstip, sport, dport, dnsrec
  				if sport or dport not in ip_convo:
  					ip_convo.append(ipaddr)
					if dnsrec not in tor_traffic:
						tor_traffic.append(dnsrec)
  
  for pkt in pkts:
	if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
	  x = pkt.getlayer(DNS).qd.qname
	  if x not in dns_names:
		dns_names.append(x)
  
  for dnsrec in tor_traffic:
	for z in dns_names:
	  if dnsrec == z:
		tor_traffic.remove(dnsrec)
  
  
  for srcip, dstip, sport, dport, dnsrec in ip_convo:
	if int(sport) != int(dport):
	  for f in tor_traffic:
		if dnsrec == f:
		  e = Host(dstip)
		  e.hostsrc = srcip
		  e.hostdst = dstip
		  e.hostsport = sport
		  e.hostdport = dport
		  e += Field('pcapsrc', request.value, displayname='Original pcap File')
		  e += Field('proto', 'tcp', displayname='Protocol')
		  e += Field('sniffMyPackets.outputfld', tmpfolder, displayname='Folder Location')
		  e.linklabel = dnsrec
		  e.linkcolor = 0xCC33FF
		  response += e
  return response
