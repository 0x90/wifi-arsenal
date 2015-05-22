#! /Usr/bin/env python

import os
import re
import csv
import sys
import pcap
import string
import time
import socket
import struct
import getopt

from framefilter import FrameFilter
from config import Configure
from netperf import Netperf

runtime = 300
ho_count = 0
snr_threshold = 0 # default

SNR = 0
SRC = 1
DST = 2

FILTER = { SNR:False,
           SRC:True,
           DST:True }

try:
   optlist, args = getopt.getopt(sys.argv[1:], "t:m:x:s:d:", 
                                 longopts=["adhoc-interface=", "monitor-interface=", "threshold=",
                                           "src-addr-filter=", "dst-addr-filter="])
except getopt.GetoptError:
   print 'usage: python py_monitoring.py -t <transmit_interface> -m <monitor_interface> -x <snr_threshold> [ -s -1 -d -1 ]'
   sys.exit(0)

for opt, args in optlist:
   if opt in ("-t", "--adhoc-interface"):
      adhoc_interface = args
   if opt in ("-m", "--monitor-interface"):
      monitor_interface = args
   if opt in ("-x", "--threshold"):
      snr_threshold = int(args)
      FILTER[SNR] = True
   if opt in ("-s", "--src-addr-filter"):
      FILTER[SRC] = False
   if opt in ("-d", "--dst-addr-filiter"):
      FILTER[DST] = False

def write_to_file(ff, ct):
   filename = "%f.csv" % exp_start
   writecsv = csv.writer(file(filename, 'w'), lineterminator='\n')

   writecsv.writerow(["HO counts", ct])
   for daddr in ff.addr_lq:
      writecsv.writerow(["ROBOHOC [%s], rtETX, EMA SNR" % daddr, ''])
      #writecsv.writerows(ff.addr_lq[daddr].rtetx) # not used since 20081228 -> rtt_measurement.py added
      writecsv.writerows(ff.addr_lq[daddr].rtetx2)

def set_interface(iface, cf):
   if cf.ip_aaddr != cf.ip_saddr:
      cmd = "iwconfig %s channel %i" % (iface, cf.channel)
      os.system(cmd)
      print "----> DONE \" %s \"" % cmd

   else:
      cmd = "iwconfig %s channel %i" % (iface, cf.channel)
      os.system(cmd)
      print "----> DONE \" %s \"" % cmd

if __name__=='__main__':
   
    exp_start = time.time()

    if len(sys.argv) < 2:
       print 'usage: sudo py_monitoring.py -t <transmit_interface> -m <monitor_interface> -x <snr_threshold> [ -s -1 -d -1 ]'
       sys.exit(0)

    working_iface_adhoc = adhoc_interface
    backup_iface_adhoc = monitor_interface
    if adhoc_interface == "ath0" and monitor_interface == "ath1":
       working_iface_monitor = re.compile('[0]').sub('2', adhoc_interface)
       backup_iface_monitor = re.compile('[1]').sub('3', monitor_interface)
    elif adhoc_interface == "ath1" and monitor_interface == "ath0":
       working_iface_monitor = re.compile('[1]').sub('3', adhoc_interface)
       backup_iface_monitor = re.compile('[0]').sub('2', monitor_interface)
    else:
       print "Please specify [ath0, ath1] for each interface. "
       sys.exit(0)
       
    print "Interfaces: [wa: %s] [wm: %s] [ba: %s] [bm: %s]" % (working_iface_adhoc, working_iface_monitor, backup_iface_adhoc, backup_iface_monitor)

    cf = Configure(working_iface_adhoc, backup_iface_adhoc)
    ff = FrameFilter(cf, snr_threshold, FILTER)
    p = pcap.pcapObject()
    p.open_live(backup_iface_monitor, 96, 0, 100)

    try:
       while 1:
          while ff.rx_frame < 10: # Approx. 100ms * 100 = 10s ; Only beacon frames counted
             apply(ff.filter, p.next())
             #ff.print_rx_filter(backup_iface_monitor)
             ff.print_tx_filter(working_iface_adhoc) # maybe 1s

          stime = time.time()
          print "loop starts %f" % stime

          # Initialization
          try:
             current_lq = ff.addr_lq[cf.ether_daddr].lq # rtetx of scanned neighbor host
          except KeyError:
             current_lq = 10.0
             print "No Link Quality of [%s] is acquired" % cf.ether_daddr

          ff.rx_frame = 0 # RX frame count set 0 for next channel
          ff.tx_frame = 0 # TX frame count set 0 for next channel
          cf.next() # Configuration for next channel
          set_interface(backup_iface_adhoc, cf) # Setup interface for next channel

          # Algorithm 2
          if ff.is_higher(cf.ether_daddr):
             #if cf.ip_aaddr != cf.ip_saddr: # When added ?
             print "Netperf Starts "
             nf = Netperf(cf.ip_daddr)
             nf.run('ping', '-q -s 1024 -c 500 -i 0.01 %s > /dev/null' % cf.ip_daddr) # since 200812152330
                #nf.run('ping', '-q -s 1024 -c 2000 -i 0.01 %s > /dev/null' % cf.ip_daddr) # since 200812121800
                #nf.run('ping', '-q -s 1024 -c 500 -i 0.01 %s > /dev/null' % cf.ip_daddr) # since 200812121703
                #nf.run('netperf', '-l 1 -H %s > /dev/null' % cf.ip_daddr) # not yet tested
             print "Netperf Ends"

          try:
             previous_lq = ff.addr_lq[cf.ether_daddr].lq
             print "cur %f, pre %f" % (current_lq, previous_lq)
             if current_lq + 0.1 < previous_lq: # previous rtetx of counterpart
                ho_count += 1
                print "HANDOVER WILL BE CONDUCTED HERE"

          except KeyError:
             print "No Link Quality of [%s] is acquired" % cf.ether_daddr

          etime = time.time()
          print "loop ends %f in %f" % (etime, etime - stime)


          if ( time.time() - exp_start ) > runtime:
             write_to_file(ff, ho_count)
             sys.exit(1)

    except KeyboardInterrupt:
       print '%s' % sys.exc_type
       print 'Shutting down'
       print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()

       write_to_file(ff, ho_count)

       for daddr in ff.addr_lq:
          print "Bitrate counter: %s %s " % (daddr, ff.addr_lq[daddr].rate)

       print "ALL frames (=ff.frame) : %i [frame]" % ff.frame
       print "RX Beacon frames (=ff.rx_frame) : %i [frame]" % ff.rx_frame
       print "Data frames (=ff.tx_frame) : %i [frame]" % ff.tx_frame

       print "%i times of handover have conducted" % ho_count

       print "%f [second] left for end..." % ( runtime - (time.time() - exp_start ))

       for daddr in ff.addr_lq:
          print "Robohoc [%s] %s" % (daddr, ff.addr_lq[daddr].rtetx2)

