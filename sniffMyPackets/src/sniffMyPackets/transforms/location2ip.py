#!/usr/bin/env python

from canari.maltego.entities import Location, IPv4Address
from canari.maltego.message import Field, UIMessage
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
    label='L4 - Convert a Location 2 IP [SmP]',
    description='Convert a sniffMyPackets Location to IP address',
    uuids=[ 'sniffMyPackets.v2.Location_2_IP' ],
    inputs=[ ( 'sniffMyPackets', Location ) ],
    debug=True
)
def dotransform(request, response):


    pcap = request.fields['pcapsrc']
    srcip = request.fields['ipaddress']
    e = IPv4Address(srcip)
    e += Field('pcapsrc', pcap, displayname='Original pcap File')
    response += e
    return response
