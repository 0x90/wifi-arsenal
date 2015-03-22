#! /usr/bin/env python

########################################
#
# wifitap.py --- WiFi injection tool through tun/tap device
#
# Copyright (C) 2011 Daniel Smith <viscous.liquid@gmail.com>
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

import os,sys,getopt,struct,re,string,logging,asyncore

# Import Psyco if available to speed up execution
try:
	import psyco
	psyco.full()
except ImportError:
	print "Psyco optimizer not installed, running anyway..."

from scapy.all import Ether,SNAP,conf
from wifitap_device import WifiTapDevice
from readers import WifiTapReader, InterfaceReader

def usage(status=0):
    print "Usage: wifitap -b <BSSID> [-o <iface>] [-i <iface>] [-s <SMAC>]"
    print "                          [-w <WEP key> [-k <key id>]] [-d [-v]] [-h]"
    print "     -b <BSSID>    specify BSSID for injection"
    print "     -o <iface>    specify interface for injection (default: ath0)"
    print "     -i <iface>    specify interface for listening (default: ath0)"
    print "     -s <SMAC>     specify source MAC address for injected frames"
    print "     -w <key>      WEP mode and key"
    print "     -k <key id>   WEP key id (default: 0)"
    print "     -r <b/g rate> B/G transmit rate"
    print "     -m <mcs rate> N transmit rate"
    print "     -t <retries>  Number of retries"
    print "     -g            Enable short guard interval"
    print "     -d            activate debug"
    print "     -v            verbose debugging"
    print "     -h            this so helpful output"
    sys.exit(status)

def parse_opts(wifitap):
    opts = getopt.getopt(sys.argv[1:],"b:o:i:s:w:k:r:m:t:gdvh")

    for opt,optarg in opts[0]:
        if opt == "-b":
            wifitap.bssid = optarg
        elif opt == "-o":
            wifitap.outface = optarg
        elif opt == "-i":
            wifitap.inface = optarg
        elif opt == "-s":
            wifitap.smac = optarg
        elif opt == "-w":
            wifitap.wepkey = optarg
        elif opt == "-k":
            wifitap.keyid = int(optarg)
        elif opt == "-r":
            wifitap.rate = int(optarg)
        elif opt == "-m":
            wifitap.mcs = int(optarg)
        elif opt == "-t":
            wifitap.retries = int(optarg)
        elif opt == "-g":
            wifitap.hgi = True
        elif opt == "-d":
            wifitap.debug = True
        elif opt == "-v":
            wifitap.verb = True
        elif opt == "-h":
            usage()

    if not wifitap.bssid:
        print "\nError: BSSID not defined\n"
        usage()

    # Match and parse BSSID
    if re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', wifitap.bssid):
        wifitap.bssid = wifitap.bssid.lower()
    else:
        print "\nError: Wrong format for BSSID\n"
        usage ()

    if wifitap.smac != '':
        # Match and parse SMAC
        if re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', wifitap.smac):
            wifitap.smac = wifitap.smac.lower()
        else:
            print "\nError: Wrong format for SMAC\n"
            usage()

    print "IN_IFACE:   %s" % wifitap.inface
    print "OUT_IFACE:  %s" % wifitap.outface
    print "BSSID:      %s" % wifitap.bssid
    if wifitap.smac != '':
        print "SMAC:       %s" % wifitap.smac

def setup_scapy(wifitap):
    logging.getLogger("scapy").setLevel(1)

    conf.iface = wifitap.outface

    # Speed optimization si Scapy does not have to parse payloads
    Ether.payload_guess=[]
    SNAP.payload_guess=[]


if __name__ == "__main__":
    wifitap = WifiTapDevice()

    parse_opts(wifitap)
    setup_scapy(wifitap)

    try:
        wifitap.open()
        wt_reader = WifiTapReader(wifitap)
        intf_reader = InterfaceReader(wifitap)

        asyncore.loop()
    # Program killed
    except KeyboardInterrupt:
        print "Stopped by user."

    #s.close()
    #os.close(f)

sys.exit()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4 autoindent
