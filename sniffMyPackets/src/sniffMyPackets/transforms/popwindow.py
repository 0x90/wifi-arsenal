#!/usr/bin/env python
import subprocess
from common.entities import RebuiltFile, GenericFile
from canari.maltego.message import Field
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
    label='L0 - Pop Open Window [SmP]',
    description='Opens a window to the folder location',
    uuids=[ 'sniffMyPackets.v2.Openswindow_2_folderlocation', 'sniffMyPackets.v2.Openswindow_2_generic' ],
    inputs=[ ( 'sniffMyPackets', RebuiltFile ), ( 'sniffMyPackets', GenericFile ) ],
    debug=False
)
def dotransform(request, response):

    folder = request.fields['sniffMyPackets.outputfld']
    subprocess.Popen(['xdg-open', folder])
    return response
