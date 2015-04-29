#!/usr/bin/env python

import logging, re, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, UserLogin
from canari.maltego.message import UIMessage
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
    label='L4 - Find FTP Creds [SmP]',
    description='Search pcap file for FTP creds',
    uuids=[ 'sniffMyPackets.v2.pcapFile2ftpCreds' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  ftp_user = 'USER'
  ftp_pass = 'PASS'
  user_lookup = []
  pass_lookup = []

  for p in pkts:
    if p.haslayer(TCP) and p.haslayer(Raw) and p.getlayer(TCP).dport == 21:
      load = p.getlayer(Raw).load
      sport = p.getlayer(TCP).sport
      if ftp_user in load:
        for s in re.finditer('USER (\w*)', load):
          user = s.group(1)
          tmp_user = user, sport
          user_lookup.append(tmp_user)
      if ftp_pass in load:
        for t in re.finditer('PASS (\w*)', load):
          passwd = t.group(1)
          tmp_passwd = passwd, sport
          pass_lookup.append(tmp_passwd)

  for xuser, xport in user_lookup:
    for xpass, uport in pass_lookup:
      if xport == uport:
        creds = 'Username: ' + xuser + '\r\nPassword: ' + xpass
        e = UserLogin(creds)
        response += e
  return response