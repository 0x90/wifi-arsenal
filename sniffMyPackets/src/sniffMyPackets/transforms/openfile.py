#!/usr/bin/env python
import os, subprocess
from common.entities import GenericFile, RebuiltFile
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
    label='L0 - Open file in application [SmP]',
    description='Tries to open the file in its default application',
    uuids=[ 'sniffMyPackets.v2.Opensfile_in_application', 'sniffMyPackets.v2.openany_file' ],
    inputs=[ ( 'sniffMyPackets', GenericFile ), ( 'sniffMyPackets', RebuiltFile ) ],
    debug=False
)
def dotransform(request, response):

    filepath = request.value
    cmd = 'xdg-open ' + filepath
    subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return response + UIMessage('Application has opened in a seperate process!!')