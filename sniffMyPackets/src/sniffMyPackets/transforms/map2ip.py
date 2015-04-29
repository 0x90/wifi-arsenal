#!/usr/bin/env python

from common.entities import Host
from canari.maltego.message import UIMessage, Field
from canari.maltego.entities import IPv4Address, Domain
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
    label='L2 - Map to IPv4Address [SmP]',
    description='Maps entity to single IP address to show relationships',
    uuids=[ 'sniffMyPackets.v2.map2ip_host' ],
    inputs=[ ( 'sniffMyPackets', Host ) ],
    debug=False
)
def dotransform(request, response):

  pcap = request.fields['pcapsrc']
  try:
    srcip = request.fields['hostdst']
  except:
    srcip = request.fields['sniffMyPackets.hostdst']

  if srcip is not None:
    e = IPv4Address(srcip)
    e += Field('pcapsrc', pcap, displayname='Original pcap File')
    response += e
    return response
  else:
    return response + UIMessage('Does not contain Source IP field')
      
