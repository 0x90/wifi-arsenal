#!/usr/bin/env python

import os, sys, hashlib
from common.entities import pcapFile, Folder, GenericFile
from canari.easygui import multenterbox
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
    label='L0 - Hash all the files [SmP]',
    description='Hash files in folder',
    uuids=[ 'sniffMyPackets.v2.hash_from_pcap', 'sniffMyPackets.v2.hash_from_folder' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ), ( 'sniffMyPackets', Folder ) ],
    debug=True
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

    file_list = []
    hash_list = []

    msg = 'Enter output file'
    title = 'L0 - Hash all the files [SmP]'
    fieldNames = ["File Name"]
    fieldValues = []
    fieldValues = multenterbox(msg, title, fieldNames)

    hash_file = fieldValues[0]

    for path, subdirs, files in os.walk(folder):
        for name in files:
            fname = name
            fpath = os.path.join(path, name)
            if fpath not in file_list:
                file_list.append(fpath)

    i = len(folder) + 1

    for s in file_list:
        fh = open(s, 'r')
        sha1hash = hashlib.sha1(fh.read()).hexdigest()
        fh = open(s, 'r')
        md5hash = hashlib.md5(fh.read()).hexdigest()
        fhash = s[i:] + ' ' + str(sha1hash) + ' ' + str(md5hash)
        if fhash not in hash_list:
            hash_list.append(fhash)
    

    f = open(hash_file, 'w')
    f.write("\n".join(hash_list))
    f.close()

    e = GenericFile(hash_file)
    e.linklabel = 'Hash File'
    e += Field('sniffMyPackets.outputfld', folder, displayname='Folder Location')
    response += e
    return response