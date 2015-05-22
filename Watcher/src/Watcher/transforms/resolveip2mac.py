#!/usr/bin/env python
from common.entities import WirelessClient
from canari.maltego.message import Field
from canari.framework import configure #, superuser
from canari.maltego.entities import IPv4Address
from canari.maltego.message import UIMessage

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Watcher Project'
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
    label='Watcher - Resolve IP addr to MAC addr',
    description='Resolve IP address to MAC addr',
    uuids=[ 'Watcher.v2.resolve_ip_2_mac' ],
    inputs=[ ( 'Watcher', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
    
    try:
        mac_addr = request.fields['ethernet.hwaddr']
    except:
        return response + UIMessage('No MAC address associated with entity')

    e = WirelessClient(mac_addr)
    response += e
    return response