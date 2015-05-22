#!/usr/bin/env python
import os, uuid
from canari.maltego.message import UIMessage, Field
from common.entities import Interface, Folder
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
    label='L0 - Create folder for storing stuff [SmP]',
    description='Create a folder from an interface entity to store stuff in',
    uuids=[ 'sniffMyPackets.v2.create_folder_int' ],
    inputs=[ ( 'sniffMyPackets', Interface ) ],
    debug=False
)
def dotransform(request, response):
    
    iface = request.value
    pkt_count = request.fields['sniffMyPackets.count']

    tmpfolder = '/tmp/'+str(uuid.uuid4())
    if not os.path.exists(tmpfolder):
        os.makedirs(tmpfolder)

    e = Folder(tmpfolder)
    e.linklabel = 'Folder Created!'
    e.interface = iface
    e += Field('sniffMyPackets.count', pkt_count, displayname='Folder Location')
    response += e
    return response
