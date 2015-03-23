#! /usr/bin/env python

######
# v1.0
# Randomize Transmit, Source, BSSID and SSID data for Assoc. Req. frames
# Source file needs to be in pcap format, or wcap (native OSX sniffer). 
# If it's not, you can convert with:
# tshark -r <input_file> -w <output_file> -F pcap
# Usage: 
# *specify source file. Example: association-randomizer.py galaxy.pcap
# *launch without source file and capture on specified channels
#######

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from random import randint
import sys, os, os.path, binascii, signal, subprocess

# clear /tmp/ from all pre-existing files that start with capture_
# sending output to /dev/null, in case no files exist
FNULL = open(os.devnull, 'w')
subprocess.Popen("rm /tmp/capture_*", shell=True, stdout=FNULL, stderr=subprocess.STDOUT)

# function to handle signals (ctrl+c)
def signal_handler(signal, frame):
        print('You pressed Ctrl+c to stop capturing...')
signal.signal(signal.SIGINT, signal_handler)

# function for running captures to gather associations
def tshark_cap():
  chan_num = raw_input('what 20MHz channel would you like to capture on? (1, 36, 40, 44, etc.) > ' )
  print 'Disconnecting from WiFi'
  subprocess.Popen("/usr/sbin/airport -z", shell=True, stdout=subprocess.PIPE).stdout.read()
  print 'setting sniff channel to channel %s' % chan_num
  subprocess.Popen("/usr/sbin/airport --channel=%s" % chan_num, shell=True, stdout=subprocess.PIPE).stdout.read()
  print 'Now associate to AP, then press Ctrl+C to stop capturing (after associating)'
  subprocess.Popen("tshark -s0 -I -i en0 -f 'not type data' -w /tmp/capture_chan%s.pcap -F pcap" % chan_num, shell=True, stdout=subprocess.PIPE).stdout.read()
  print('Saved pcap as /tmp/capture_chan%s.pcap' % chan_num)
  finished = raw_input('Would you like to capture on another channel? (y/n)> ')
  if finished == 'y' or finished == 'yes':
    tshark_cap()
  else:
    print 'Now merging all pcaps to /tmp/capture_allpcaps.pcap...'
    subprocess.Popen("mergecap -F pcap -w /tmp/capture_allpcaps.pcap /tmp/capture_*", shell=True, stdout=subprocess.PIPE).stdout.read()
    print 'Merge complete, merged file ready for processing...'
    return

# function to apply to each frame
converted = []
pkt_num = 0
def associations(frame):
  global pkt_num
  if frame.type == 0 and frame.subtype == 0:
    print "Association Request found..."
    print "Original info:\n Client: %s\n AP: %s\n BSSID: %s\n SSID: %s" % (frame.addr2, frame.addr1, frame.addr3, frame.info)
    question = raw_input("Randomize this Association Request? (y/n) > ")
    if question == 'y' or question == 'yes':
      frame.addr1 = '11:11:11:11:11:11'
      frame.addr2 = '22:22:22:22:22:22'
      frame.addr3 = '11:11:11:11:11:11'
      ssid_taglen = len(frame.info)
      frame.info = ''.join(["%s" % randint(0, 9) for num in range(0, ssid_taglen)])
      print "New info:\n Client: %s\n AP: %s\n BSSID: %s\n SSID: %s" % (frame.addr2, frame.addr1, frame.addr3, frame.info)
      # write the new randomized frame to file, with increment
      wrpcap('assoc' + '_randomized_' + str(pkt_num) + '.pcap', frame)
      print "Wrote new pcap file to ./assoc%s%s%s" % ('_randomized_',pkt_num, '.pcap')
      pkt_num = int(pkt_num) + 1
      hitkey = raw_input("Hit enter to continue...")
    else:
      print "moving on..."

# Check FCS on 802.11 frame, return True is FCS is good or False otherwise
# Note: if FCS invalid (or not present) frame won't be processed.
# If you'd like to process frames w/ out this check, comment out the following function
# and change the below line "prn = checkfcs" to: "prn = associations"

magic = 0x2144df1c
pnum = 0
def checkfcs(pkt):
  global pnum 
  pnum = pnum + 1
  if pkt.haslayer(Dot11):
    qcrc = binascii.crc32(pkt.payload.__str__()) & 0xffffffff
    if qcrc == magic:
      print "Analyzing frame %d" % pnum
      associations(pkt)
    else:
      print "Frame %s failed FCS" % pnum

# merge pcaps if necessary
def merge_caps():
  subprocess.Popen("mergecap -F pcap -w ./allpcaps.pcap ./assoc_randomized_*", shell=True, stdout=subprocess.PIPE).stdout.read()
  print "Saved combined randomized pcap as ./allpcaps.pcap\n"

# determine if sniffing live, or if pcap passed as argument
if len(sys.argv) < 2:
  print "You didn't specify an input file, proceeding with live captures...\n" 
  # check if script is running as root
  euid = os.geteuid()
  if euid != 0:
    print "*WARNING* YOU MUST BE ROOT TO PERFORM LIVE CAPTURES (su or use sudo)\n"
    print "Example on OSX: sudo /opt/local/bin/python2.7 association-randomizer.py"
    print "Script not started as root. exiting..."
    sys.exit(0)
  print "NOTE: To exit this script at any time press Ctrl+d"
  tshark_cap()
  in_file = '/tmp/capture_allpcaps.pcap'
  sniff(offline=in_file, prn = checkfcs)
  merge = raw_input("Would you like to merge all individual randomized pcaps into one? (y/n)> ")
  if merge == 'y' or merge == 'yes':
    merge_caps()
  else:
    print "Complete\n"
else:
  in_file = str(sys.argv[1])
  sniff(offline=in_file, prn = checkfcs)
  merge = raw_input("Would you like to merge all individual randomized pcaps into one? (y/n)> ")
  if merge == 'y' or merge == 'yes':
    merge_caps()
  else:
    print "Complete\n"

sys.exit(0)
