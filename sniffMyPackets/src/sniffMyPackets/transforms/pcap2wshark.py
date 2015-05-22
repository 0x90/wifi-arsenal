#!/usr/bin/env python

import os
#from canari.maltego.utils import debug, progress
from common.entities import pcapFile
from canari.maltego.message import UIMessage
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
    label='L0 - Open in Wireshark [SmP]',
    description='Opens a pcap file in Wireshark',
    uuids=[ 'sniffMyPackets.v2.pcap2Wireshark' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
	
	pcap = request.value
	cmd = 'wireshark ' + pcap
	os.system(cmd)
	return response + UIMessage('Wireshark has closed!')
