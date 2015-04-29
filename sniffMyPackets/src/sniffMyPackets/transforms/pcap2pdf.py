#!/usr/bin/env python

from pyx import *
import logging
from time import time as clock
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, GenericFile
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
    label='L3 - Export pcap to PDF [SmP]',
    description='Export a pcap file to a PDF file',
    uuids=[ 'sniffMyPackets.v2.pcap_2_pdf' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
    conf.verb = 0 # turn off the annoying....'s'
    pcap = request.value
    pkts = rdpcap(pcap)
    new_file = ''
    tstamp = int(clock())
    
    try:
        tmpfolder = request.fields['sniffMyPackets.outputfld']
    except:
        return response + UIMessage('No output folder defined, run the L0 - Prepare pcap transform')

    if 'stream' not in pcap:
        new_file = tmpfolder + '/' + str(tstamp) + '.pdf'
    else:
        new_file = tmpfolder + '/' + request.value[42:-5] + '.pdf'

    pkts.pdfdump(filename=new_file)
    e = GenericFile(new_file)
    e.linklabel = 'PDF File'
    response += e
    return response
