#!/usr/bin/env python

import logging, os, glob, uuid, re, hashlib
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
from common.dissectors.dissector import *
from canari.maltego.message import Field, Label, UIMessage
from common.entities import pcapFile, RebuiltFile
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = 'The additional Scapy dissectors was written by cs_saheel@hotmail.com and can be found here: https://github.com/cssaheel/dissectors'

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
    label='L3 - Rebuild files from pcap [SmP]',
    description='Rebuilds files from within pcap file',
    uuids=[ 'sniffMyPackets.v2.rebuildFilesFrompcap' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
    
    try:
        folder = request.fields['sniffMyPackets.outputfld']
    except:
        return response + UIMessage('No output folder defined, run the L0 - Prepare pcap transform')
    
    tmpfolder = folder + '/files'

    if not os.path.exists(tmpfolder):
        os.makedirs(tmpfolder) 
    list_files = []
    file_types = []
    objects = []
    
    dissector = Dissector() # instance of dissector class
    dissector.change_dfolder(tmpfolder)
    pkts = dissector.dissect_pkts(request.value)
    list_files = glob.glob(tmpfolder+'/*')
    
    for i in list_files:
      if 'stream' not in i:
        cmd = 'file ' + i
        x = os.popen(cmd).read()
        fhash = ''
        fh = open(i, 'rb')
        fhash = hashlib.sha1(fh.read()).hexdigest()
        file_details = x, fhash
        if file_details not in file_types:
          file_types.append(file_details)
      
    for x, fhash in file_types:
      for t in re.finditer('^([^:]*)',x):
        fpath = t.group(1)
      for s in re.finditer('([^:]*)(\s)',x):
        ftype = s.group(1)
        z = fpath, ftype, fhash
        if z not in objects:
          objects.append(z)
    
    for fpath, ftype, fhash in objects:
      e = RebuiltFile(fpath)
      e.ftype = ftype
      e.fhash = fhash
      e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
      e += Field('sniffMyPackets.outputfld', folder, displayname='Folder Location')
      e.linklabel = ftype
      e.linkcolor = 0xFF9900
      response += e
    return response