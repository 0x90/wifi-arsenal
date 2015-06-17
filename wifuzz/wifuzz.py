#!env python

# Copyright notice
# ================
#
# Copyright (C) 2011
#     Roberto  Paleari    <roberto.paleari@gmail.com>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# WiFuzz is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.

"""
Access Point 802.11 stack fuzzer

Remember to put your wireless NIC into 'monitor mode' with something like this:

$ sudo rmmod iwlagn
$ sudo modprobe iwlagn
$ sudo ifconfig wlan0 down
$ sudo iwconfig wlan0 mode monitor
$ sudo ifconfig wlan0 up
"""

import sys
import signal, os, time
import getopt

from scapy.config import *
from scapy.utils import *
from scapy.all import get_if_raw_hwaddr
conf.verb=0

from   common   import log, WiExceptionTimeout
from   widriver import  WifiDriver
import wifuzzers

DEFAULT_IFACE       = "wlan0"
DEFAULT_PCAP_DIR    = "/dev/shm"
DEFAULT_PING_TIMOUT = "60"

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:p:s:t")
    except getopt.GetoptError, e:
        print str(e)
        showhelp()
        exit(1)

    opts = dict([(k.lstrip('-'), v) for (k,v) in opts])

    if 'h' in opts or 's' not in opts or len(args) != 1:
        showhelp()
        exit(0)

    fuzztype    = args[0]
    conf.iface  = opts.get('i', DEFAULT_IFACE)
    conf.tping  = opts.get('p', DEFAULT_PING_TIMOUT)

    if not conf.tping.isdigit():
        log("[!] Ping timeout (-p) must be a valid integer", "MAIN")
        exit(2)

    conf.tping = int(conf.tping)
    if conf.tping <= 0:
        log("[!] Ping timeout (-p) must be greater than zero", "MAIN")
        exit(2)

    conf.outdir = opts.get('o', DEFAULT_PCAP_DIR)
    ssid        = opts.get('s')
    localmac    = str2mac(get_if_raw_hwaddr(conf.iface)[1])
    testmode    = 't' in opts
    
    log("Target SSID: %s; Interface: %s; Ping timeout: %d; PCAP directory: %s; Test mode? %s; Fuzzer(s): %s;" % \
            (ssid, conf.iface, conf.tping, conf.outdir, testmode, fuzztype), "MAIN")

    wifi = WifiDriver(ssid = ssid, tping = conf.tping, outdir = conf.outdir,
                      localmac = localmac, testmode = testmode, verbose = 1)

    # Get the MAC address of the AP
    try:
        mac = wifi.waitForBeacon()
    except WiExceptionTimeout, e:
        log("No beacon from target AP after %d seconds" % conf.tping, "MAIN")
        sys.exit(1)

    wifi.apmac = mac

    # Fuzz!
    wifi.fuzz(fuzztype = fuzztype)

def showhelp():
    from types import ClassType

    print """\
-=- WiFuzz: Access Point 802.11 STACK FUZZER -=-
Syntax: python %s -s <ssid> [options] <fuzzer>(,<fuzzer>)*

Available options:
-h       Show this help screen
-i       Network interface (default: %s)
-o       Output directory for PCAP files (default: %s)
-p       Ping timeout (default: %d seconds)
-s       Set target AP SSID
-t       Enable test mode

Remember to put your Wi-Fi card in monitor mode. Your driver must support
traffic injection.
""" % (sys.argv[0], DEFAULT_IFACE, DEFAULT_PCAP_DIR, int(DEFAULT_PING_TIMOUT))

    l = []
    for m in dir(wifuzzers):
        o = getattr(wifuzzers, m)
        if not isinstance(o, ClassType) or o == wifuzzers.WifiFuzzer or not issubclass(o, wifuzzers.WifiFuzzer):
            continue
        l.append((o.getName(), o.state, o.__doc__.strip(".")))
    l.sort()
    m = max([len(x[2]) for x in l])

    print "Available fuzzers:"
    s = "| %s | %s | %s |" % ("Name".center(10), "State".center(20), "Description".center(m))
    print "-"*len(s)
    print s
    print "-"*len(s)
    for name, state, desc in l:
        print "| %s | %s | %s |" % (name.center(10), wifuzzers.state_to_name(state).center(20), desc.ljust(m))
    print "-"*len(s)
    print

if __name__ == "__main__":
    main()
