#!/usr/bin/env python

import os, sys, email, errno, mimetypes, hashlib, re
from random import randint
from common.entities import EmailMessage, RebuiltFile
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
    label='L4 - Find SMTP Attachments [SmP]',
    description='Looks for email attachments in rebuilt files and rebuilds them',
    uuids=[ 'sniffMyPackets.v2.unpackattachment2folder' ],
    inputs=[ ( 'sniffMyPackets', RebuiltFile ) ],
    debug=True
)
def dotransform(request, response):
  
  msgdata = []
  filelist = []
  msgfile = request.value
  lookFor = 'DATA'
  tmpfolder = request.fields['sniffMyPackets.outputfld']
  
  # split the original file into two parts, message and header and save as lists
  with open(msgfile, mode='r') as msgfile:
    reader = msgfile.read()
    for i, part in enumerate(reader.split(lookFor)):
      #if i == 0:
	#headerdata.append(part.split("\r\n"))
      if i == 1:
	msgdata.append(part.strip())

  
  for item in msgdata:
    rnd = str(randint(1, 100))
    newfolder = tmpfolder + '/' + rnd 
    if not os.path.exists(newfolder): os.makedirs(newfolder)
    filename = tmpfolder + '/' + 'msgdata.msg'
    fb = open(filename, 'w')
    fb.write('%s\n' % item)
    fb.close()
  
    fp = open(filename)
    msg = email.message_from_file(fp)
    fp.close()

    counter = 1
    for part in msg.walk():
      if part.get_content_maintype() == 'multipart':
	  continue
      filename = part.get_filename()
      if not filename:
	  ext = mimetypes.guess_extension(part.get_content_type())
	  if not ext:
	      ext = '.bin'
	  filename = 'part-%03d%s' % (counter, ext)
      counter += 1
     
      savefile = newfolder + '/' + filename
      fp = open(savefile, 'wb')
      fp.write(part.get_payload(decode=True))
      fp.close()
      
      # Hash the file and return a SHA1 sum
      sha1sum = ''
      fh = open(savefile, 'rb')
      sha1sum = hashlib.sha1(fh.read()).hexdigest()
      
      # Determine the file type and use as link label
      cmd = 'file ' + savefile
      x = os.popen(cmd).read()
      for s in re.finditer('([^:]*)(\s)',x):
		ftype = s.group(1)
      
      e = EmailMessage(savefile)
      e.emailhash = sha1sum
      e.emailtype = ftype
      e += Field('newfolder', newfolder, displayname='Folder Location')
      e.linklabel = ftype
      response += e
    return response