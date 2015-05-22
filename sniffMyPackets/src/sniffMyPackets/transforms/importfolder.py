#!/usr/bin/env python
import glob, os, hashlib
from common.entities import Folder, pcapFile
from canari.maltego.message import Field, Label, UIMessage
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
    label='L0 - Import pcap(s) from folder [SmP]',
    description='Imports pcap files from a specified folder',
    uuids=[ 'sniffMyPackets.v2.import_from_folder' ],
    inputs=[ ( 'sniffMyPackets', Folder ) ],
    debug=True
)
def dotransform(request, response):

    folder = request.value
    file_list = []
    file_ext = ['.pcap', '.cap']
    try:
        if not os.path.exists(folder):
            return response + UIMessage('Whoops, that folder doesnt exist')
    except:
        pass

    file_list = glob.glob(folder+'/*')

    for x in file_list:
        sha1hash = ''
        md5hash = ''
        for s in file_ext:
            if s in x:
                fh = open(x, 'rb')
                sha1hash = hashlib.sha1(fh.read()).hexdigest()
                fh.close()
                fh = open(x, 'rb')
                md5hash = hashlib.md5(fh.read()).hexdigest()
                fh.close()
                e = pcapFile(x)
                e.sha1hash = sha1hash
                e.outputfld = folder
                e.md5hash = md5hash
                response += e
            else:
                pass
    return response
