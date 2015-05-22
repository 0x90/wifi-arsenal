#!/usr/bin/env python

import glob, os, zipfile, hashlib, re
from random import randint
from common.entities import EmailMessage, GenericFile
from canari.maltego.message import UIMessage, Field, Label
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
    label='L4 - Unzip Attachment [SmP]',
    description='Takes a email attachment and unzips content',
    uuids=[ 'sniffMyPackets.v2.unzip2files' ],
    inputs=[ ( 'sniffMyPackets', EmailMessage ) ],
    debug=True
)
def dotransform(request, response):
  
  target = request.value
  filepath = request.fields['newfolder'] 
  list_files = []
  file_details = []
  
  # Create new folder for the extracted files
  rnd = str(randint(1, 100))
  newfolder = filepath + '/' + rnd
  if not os.path.exists(newfolder): os.makedirs(newfolder)
  
  # Check the file extension and if applicable unzip the file to a new folder then store the files
  if target.endswith(".zip") or target.endswith(".docx"):
	uzip = zipfile.ZipFile(target)
	uzip.extractall(newfolder)
	rootdir = newfolder
	for root, subFolders, files in os.walk(rootdir):
	  for file in files:
		list_files.append(os.path.join(root, file))
  else:
	return response + UIMessage('Sorry not the right type of file')
  
  # Iterate through the list of files and calculate the SHA1 hash, the filetype
  for i in list_files:
	sha1sum = ''
	fh = open(i, 'rb')
	sha1sum = hashlib.sha1(fh.read()).hexdigest()
	
	cmd = 'file ' + i
	x = os.popen(cmd).read()
	for s in re.finditer('([^:]*)(\s)',x):
	  ftype = s.group(1)
	
	file_detail = i, newfolder, sha1sum, ftype
	if file_detail not in file_details:
	  file_details.append(file_detail)
  
  # Create the new entity for each file with the details from above
  for fname, ffolder, fhash, ftype in file_details:
	e = GenericFile(fname)
	e += Field('ffolder', ffolder, displayname='File Location')
	e += Field('fhash', fhash, displayname='SHA1 Hash')
	e += Field('ftype', ftype, displayname='File Type')
	e.linklabel = ftype
	e.linkcolor = 0x75337D
	response += e
  return response
