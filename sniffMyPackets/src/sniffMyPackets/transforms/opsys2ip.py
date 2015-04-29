#!/usr/bin/env python
from canari.maltego.entities import BuiltWithTechnology, IPv4Address
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
    label='L4 - Operating System to IP [SmP]',
    description='Returns IP from OS determined by SmP',
    uuids=[ 'sniffMyPackets.v2.opsys_2_ip' ],
    inputs=[ ( 'sniffMyPackets', BuiltWithTechnology ) ],
    debug=False
)
def dotransform(request, response):

    try:
        s_ip = request.fields['source_ip']
        pcap = request.fields['pcapsrc']
    except:
        return response + UIMessage('Sorry this isnt a SmP OS Type')

    e = IPv4Address(s_ip)
    e += Field('pcapsrc', pcap, displayname='Original pcap File')
    response += e
    return response
