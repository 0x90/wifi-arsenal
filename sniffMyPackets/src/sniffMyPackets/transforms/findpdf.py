#!/usr/bin/env python

import os, logging, uuid
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, RebuiltFile
from canari.maltego.message import Field, Label
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
    label='L3 - Find & Rebuild PDF [SmP]',
    description='Looks for PDF files in pcap and rebuilds them',
    uuids=[ 'sniffMyPackets.v2.findpdf_rebuild' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

  pkts = rdpcap(request.value)
  artifact = 'Content-Type: application/pdf'
  ack = ''
  cfile = []
  start = str('%PDF-')
  end = ['%%EOF','.%%EOF', '.%%EOF.', '..%%EOF..']
  tmpfile = '/tmp/tmp.pdf'
  tmpfolder = request.fields['sniffMyPackets.outputfld']

  pdffile = tmpfolder + '/output.pdf'

  outfile = open(tmpfile, 'w')
  outfile2 = open(pdffile , 'w')

  for x in pkts:
    if x.haslayer(Raw):
      raw = x.getlayer(Raw).load
      if artifact in raw:
        ack = str(x.getlayer(TCP).ack)
	
  for p in pkts:
    if p.haslayer(TCP) and p.haslayer(Raw) and (p.getlayer(TCP).ack == int(ack) or p.getlayer(TCP).seq == int(ack)):
      raw = p.getlayer(Raw).load
      cfile.append(raw)

  x = ''.join(cfile)

  # Write the file out to outfile variable
  outfile.writelines(x)
  outfile.close()

  # Open the temp file, cut the HTTP headers out and then save it again as a PDF
  total_lines = ''
  firstcut = ''
  secondcut = ''
  final_cut = ''

  f = open(tmpfile, 'rb').readlines()

  total_lines = len(f)

  for x, line in enumerate(f):
    if start in line:
      firstcut = int(x)

  for y, line in enumerate(f):
    for t in end:
      if t in line:
        # print t, y
        secondcut = int(y)# + 1

  f = f[firstcut:]

  if int(total_lines) - int(secondcut) != 0:
    final_cut = int(total_lines) - int(secondcut)
    f = f[:-final_cut]
    outfile2.writelines(f)
    outfile2.close()
  else:
    outfile2.writelines(f)
    outfile2.close()

  e = RebuiltFile(pdffile)
  e.linklabel = 'PDF File'
  e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
  e += Field('sniffMyPackets.outputfld', tmpfolder, displayname='Folder Location')
  e.linkcolor = 0xFF9900
  response += e
  return response
