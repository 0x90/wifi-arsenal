#!/usr/bin/env python

import os, sys, re
from common.entities import pcapFile
from canari.maltego.entities import BuiltWithTechnology
from canari.maltego.message import Field, Label
from canari.config import config
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
    label='L4 - Determine OS [SmP]',
    description='Reads a pcap file and tries to determine OS',
    uuids=[ 'sniffMyPackets.v2.pcap_2_operatingsys' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
    
    p0f = config['locations/p0f']
    pcap = request.value
    cmd = p0f + ' -s ' + pcap + ' -NUql'
    p0f_list = []
    src_ip = []  
    p = os.popen(cmd).readlines()
    for x in p:
        s_ip = ''
        s_os = ''
        for s in re.finditer('(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):\d{1,5} - (\S*.\S*)', x):
            s_ip = s.group(1)
            s_os = s.group(2)
        rec = s_ip, s_os
        if rec not in p0f_list:
            p0f_list.append(rec)
    
    for s_ip, s_os in p0f_list:
        if s_os == '':
            pass
        else:
            e = BuiltWithTechnology(s_os)
            e += Field('source_ip', s_ip, displayname='Source IP', matchingrule='strict')
            e += Field('pcapsrc', pcap, displayname='Original pcap File')
            response += e
    return response
