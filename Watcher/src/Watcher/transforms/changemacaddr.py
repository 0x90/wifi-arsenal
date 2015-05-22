#!/usr/bin/env python
import random, os
from common.entities import Interface, MACAddress
from canari.framework import configure, superuser

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

@superuser
@configure(
    label='Watcher - Change MAC Address',
    description='Change your interface MAC address',
    uuids=[ 'Watcher.v2.change_mac_addr' ],
    inputs=[ ( 'Watcher', Interface ) ],
    debug=False
)
def dotransform(request, response):
    
    iface = request.value
    mac = [0x00, random.randint(0x00, 0x7f), random.randint(0x00, 0x7f), random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)] 
    new_mac = ':'.join(map(lambda x: "%02x" % x, mac))
    cmd = 'ifconfig ' + iface + ' down && ifconfig ' + iface + ' hw ether ' + new_mac + ' && ifconfig ' + iface + ' up'
    os.system(cmd)

    e = MACAddress(new_mac)
    response += e
    return response
