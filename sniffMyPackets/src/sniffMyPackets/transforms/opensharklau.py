#!/usr/bin/env python
import os
from common.entities import DecodeAs
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
    label='L0 - Open Wireshark with lua [SmP]',
    description='Opens Wireshark with custom Lua decode',
    uuids=[ 'sniffMyPackets.v2.open_wireshark_lua' ],
    inputs=[ ( 'sniffMyPackets', DecodeAs ) ],
    debug=True
)
def dotransform(request, response):

    pcap = request.fields['pcapsrc']
    lua_file = request.value

    cmd = 'wireshark -Xlua_script:' + lua_file + ' ' + pcap
    os.system(cmd)
    return response + UIMessage('Wireshark has closed!')
