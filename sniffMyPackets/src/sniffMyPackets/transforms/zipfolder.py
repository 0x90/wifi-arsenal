#!/usr/bin/env python

import zipfile, os, hashlib
from canari.easygui import multenterbox
from common.entities import pcapFile, Folder, ZipFile
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
    label='L0 - Zip pcap folder [SmP]',
    description='Zip contents of a folder based on folder',
    uuids=[ 'sniffMyPackets.v2.zip_from_pcap', 'sniffMyPackets.v2.zip_from_folder' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ), ( 'sniffMyPackets', Folder ) ],
    debug=False
)
def dotransform(request, response):
    
    folder = ''
    try:
        if 'sniffMyPackets.outputfld' in request.fields:
            folder = request.fields['sniffMyPackets.outputfld']
        else:
            folder = request.value
    except:
        return response + UIMessage('No folder created or specified')

    msg = 'Enter output filename (including path)'
    title = 'L0 - Zip pcap folder [SmP]'
    fieldNames = ["File Name"]
    fieldValues = []
    fieldValues = multenterbox(msg, title, fieldNames)

    save_file = fieldValues[0]
    
    def zipdir(path, zip):
        for root, dirs, files in os.walk(path):
            for file in files:
                zip.write(os.path.join(root, file))

    myzip = zipfile.ZipFile(save_file, 'w')
    zipdir(folder, myzip)
    myzip.close()

    fh = open(save_file, 'rb')
    sha1hash = hashlib.sha1(fh.read()).hexdigest()

    fh = open(save_file, 'rb')
    md5hash = hashlib.md5(fh.read()).hexdigest()

    e = ZipFile(save_file)
    e.zipmd5hash = md5hash
    e.zipsha1hash = sha1hash
    e.linklabel = 'Zip File'
    e += Field('outputfld', folder, displayname='Folder Location')
    response += e
    return response
