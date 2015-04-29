#!/usr/bin/env python


import logging, base64, re
from common.entities import pcapFile, RebuiltFile
from canari.maltego.entities import EmailAddress
from canari.maltego.message import Field, Label, MatchingRule
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
    label='L4 - SMTP Email Address Hunt [SmP]',
    description='Reads a file and looks for email addresses',
    uuids=[ 'sniffMyPackets.v2.smtpemailaddress' ],
    inputs=[ ( 'sniffMyPackets', RebuiltFile ) ],
    debug=False
)
def dotransform(request, response):
  
  emailaddr = []
  msgfile = request.value
  lookFor = ['To', 'From']
  tmpfolder = request.fields['sniffMyPackets.outputfld']
  
  with open(msgfile, mode='r') as msgfile:
    reader = msgfile.read()
    reader = str(reader)
    for x in lookFor:
      if x in reader:
        for s in re.finditer('RCPT TO: <([\w.-]+@[\w.-]+)>', reader):
          to_addr = s.group(1), 'mail_to'
          emailaddr.append(to_addr)
        for t in re.finditer('MAIL FROM: <([\w.-]+@[\w.-]+)>', reader):
          from_addr = t.group(1), 'mail_from'
          emailaddr.append(from_addr)

  
	
  for addr, addrfield in emailaddr:
    e = EmailAddress(addr)
    e.linklabel = addrfield
    e += Field('filelocation', request.value, displayname='File Location', matchingrule='loose')
    e += Field('emailaddr', addrfield, displayname='Header Info')
    response += e
  return response