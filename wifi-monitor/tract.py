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

from pexpect import *

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
      writecsv.writerow(["ROBOHOC [%s], timestamp, rtETX, EMA SNR" % daddr, ''])
      #writecsv.writerows(ff.addr_lq[daddr].rtetx) # not used since 20081228 -> rtt_measurement.py added
      writecsv.writerows(ff.addr_lq[daddr].rtetx2)

def get_switch():
  """docstring for main"""
  child = spawn("telnet 127.0.0.1 10000")
  child.expect("Click::ControlSocket/(\d*\.\d*)\r\n")
  child.sendline("read switch.switch")
  child.expect("(\d*) Read handler '\w*\.\w*' OK")
  child.expect("DATA\s*(\d*)\r\n")
  data = int(child.match.group(1))
  switch = int(child.read(data))
  return switch

def set_switch_and_gw(switch, gw):
  child = spawn("telnet 127.0.0.1 10000")
  child.expect("Click::ControlSocket/(\d*\.\d*)\r\n")
  child.sendline("write switch.switch %d" % switch)
  child.expect("(\d*) Write handler '(\w*\.\w*)' OK")
  child.sendline("write dst%d.set %s" % (switch, gw)) 
  child.expect("(\d*) Write handler '(\w*\.\w*)' OK")
  print "SET SWITCH AND GW"

def set_interface(iface, cf):
   print "cf.ip_aaddr: %s, cf.ip_saddr: %s" % (cf.ip_aaddr, cf.ip_saddr)
   if cf.ip_aaddr == cf.ip_saddr:
      cmd = "iwconfig ath%s channel %i" % (iface, cf.channel)
      os.system(cmd)
      print "----> DONE \" %s \"" % cmd

   else:
      cmd = "iwconfig ath%d channel %d && ifconfig ath%d %s netmask 255.255.255.0" % (iface, cf.channel, iface, cf.ip_saddr)
      os.system(cmd)
      print "----> DONE \" %s \"" % cmd

if __name__=='__main__':
   
    exp_start = time.time()

    if len(sys.argv) < 2:
       print 'usage: sudo tract.py -t <transmit_interface> -m <monitor_interface> -x <snr_threshold> [ -s -1 -d -1 ]'
       sys.exit(0)

    try:
       while 1:
          working_iface_adhoc = adhoc_interface
          backup_iface_adhoc = monitor_interface

          working = get_switch()
          backup = int(not working)

          if adhoc_interface == "ath0" and monitor_interface == "ath1":
             working_iface_monitor = re.compile('[0]').sub('2', adhoc_interface)
             backup_iface_monitor = re.compile('[1]').sub('3', monitor_interface)
          elif adhoc_interface == "ath1" and monitor_interface == "ath0":
             working_iface_monitor = re.compile('[1]').sub('3', adhoc_interface)
             backup_iface_monitor = re.compile('[0]').sub('2', monitor_interface)
          else:
             print "Please specify [ath0, ath1] for each interface. "
             sys.exit(0)
       
          print "Current Interfaces: [wa: %s] [wm: %s] [ba: %s] [bm: %s]" % (working_iface_adhoc, working_iface_monitor, backup_iface_adhoc, backup_iface_monitor)
          print "Current Interface: [wa: ath%s] [ba: ath%s]" % (working, backup)
          
          cf = Configure(working_iface_adhoc, backup_iface_adhoc)
          ff = FrameFilter(cf, snr_threshold, FILTER)
          p = pcap.pcapObject()
          p.open_live(backup_iface_monitor, 96, 0, 100)

          while 1:
             while ff.rx_frame < 101: # Approx. 100ms * 100 = 10s ; Only beacon frames counted
                apply(ff.filter, p.next())
                #ff.print_tx_filter(working_iface_adhoc) # maybe 1s

             stime = time.time()
             #print "loop starts %f" % stime

             try:
                for daddr in ['00:80:92:3e:18:11', '00:80:92:3e:18:18']:
                   print "XXXXXXXXXXXXXXXX"
                   ff.addr_lq[daddr].refresh(ff.addr_lq[daddr].snr.emavalue(0.8), ff.timestamp) # calc rtETX
             except KeyError:
                print "No Beacon Frame of [%s] is acquired" % daddr

             #Initialization
             try:
                current_lq = ff.addr_lq[cf.ether_daddr].lq # rtetx of transmitting iface
             except KeyError:
                current_lq = 10.0
                print "No Link Quality of [%s] is acquired" % cf.ether_daddr

             ff.rx_frame = 0 # RX frame count set 0 for next channel
             ff.tx_frame = 0 # TX frame count set 0 for next channel

             cf.next() # Configuration for next channel
             set_interface(backup, cf) # Setup interface for next channel

             #Algorithm 2
             print "cf.ether_daddr: %s" % cf.ether_daddr
             if ff.is_higher(cf.ether_daddr):
                print "Netperf Starts "
                nf = Netperf(cf.ip_daddr)
                nf.run('ping', '-q -s 1024 -c 500 -i 0.01 %s > /dev/null' % cf.ip_daddr) # since 200812152330
                   #nf.run('ping', '-q -s 1024 -c 2000 -i 0.01 %s > /dev/null' % cf.ip_daddr) # since 200812121800
                   #nf.run('ping', '-q -s 1024 -c 500 -i 0.01 %s > /dev/null' % cf.ip_daddr) # since 200812121703
                   #nf.run('netperf', '-l 1 -H %s > /dev/null' % cf.ip_daddr) # not yet tested
                print "Netperf Ends"

             try:
                lq_link1 = ff.addr_lq['00:80:92:3e:18:11'].lq # link1 = robohoc46
                lq_link2 = ff.addr_lq['00:80:92:3e:18:18'].lq # link2 = robohoc56
                if cf.ether_daddr == '00:80:92:3e:18:11':
                   tmp_lq = lq_link1
                elif cf.ether_daddr == '00:80:92:3e:18:18':
                   tmp_lq = lq_link2
                else:
                   sys.exit(1)

                print "current_lq: %f, tmp_lq['%s']: %f" % (current_lq, cf.ether_daddr, tmp_lq)

                if tmp_lq + 0.1 < current_lq: # 0.1 should be changed
                   ho_count += 1
                   tmp = adhoc_interface
                   adhoc_interface = monitor_interface
                   monitor_interface = tmp

                   # L2VPN switching
                   #set_interface(backup, cf)
                   set_switch_and_gw(backup, cf.ip_daddr)

                   print "HANDOVER WAS CONDUCTED"
                   #p.close()

                   break

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
          
          
