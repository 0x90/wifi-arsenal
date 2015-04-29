#!/usr/bin/env python
import hashlib
from common.entities import pcapFile, WarningAlert
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
    'dotransform'
]

#@superuser
@configure(
    label='L5 - Extract Alert pcap file',
    description='Outputs alert pcap file as entity',
    uuids=[ 'sniffMyPackets.v2.extractalert_2_pcap' ],
    inputs=[ ( 'sniffMyPackets', WarningAlert ) ],
    debug=True
)
def dotransform(request, response):
    
    try:
        output_file = request.fields['dumpfile']
        folder = request.fields['sniffMyPackets.outputfld']
    except:
        return response + UIMessage('No Alert pcap available..sorry.')

    # Hash the file and return a SHA1 sum
    fh = open(output_file, 'rb')
    sha1sum = hashlib.sha1(fh.read()).hexdigest()

    # Hash the file and return a MD5 sum
    fh = open(output_file, 'rb')
    md5sum = hashlib.md5(fh.read()).hexdigest()

    e = pcapFile(output_file)
    e.sha1hash = sha1sum
    e.outputfld = folder
    e.md5hash = md5sum
    response += e
    return response