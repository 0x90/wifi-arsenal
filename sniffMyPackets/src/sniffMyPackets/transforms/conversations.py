#!/usr/bin/env python

import logging, os, pygraph
from time import time as clock
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, GenericFile
from canari.maltego.message import Field, Label, UIMessage
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = 'The code for generating the jpg is taken from the original Scapy implementation,\
               however using the conversations() module didnt work so ported it across' 

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
    label='L0 - Output Conversations to JPG [SmP]',
    description='Creates a jpg of conversations in a pcap file',
    uuids=[ 'sniffMyPackets.v2.conversations' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    pkts = rdpcap(pcap)
    getsrc = lambda x:x.getlayer(IP).src
    getdst = lambda x:x.getlayer(IP).dst
    new_file = ''
    tstamp = int(clock())

    try:
        tmpfolder = request.fields['sniffMyPackets.outputfld']
    except:
        return response + UIMessage('No output folder defined, run the L0 - Prepare pcap transform')

    if 'stream' not in pcap:
        new_file = tmpfolder + '/' + str(tstamp) + '.jpg'
    else:
        new_file = tmpfolder + '/' + request.value[42:-5] + '.jpg'
    
    format = 'jpg'    
    conv = {}
    for p in pkts:
        try:
            c = (getsrc(p), getdst(p))
        except:
            continue
        conv[c] = conv.get(c,0)+1

    gr = 'digraph "conv" {\n'
    for s,d in conv:
        gr += '\t "%s" -> "%s"\n' % (s,d)
    gr += "}\n"
    w,r = os.popen2("dot -T%s -o%s" % (format, new_file))
    w.write(gr)
    w.close
    
    e = GenericFile(new_file)
    e.linklabel = 'JPG File'
    e += Field('sniffMyPackets.outputfld', tmpfolder, displayname='Folder Location')
    response += e
    return response
