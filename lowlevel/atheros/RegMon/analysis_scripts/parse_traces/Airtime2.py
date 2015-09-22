#!/usr/bin/python
# coding: utf8
#
# Copyright (c) 2007 OLPC
# Author: Ricardo Carrano <carrano at laptop.org>
# Version 0.1.2
#
# this program is free software; you can redistribute it and/or modify
# it under the terms of the gnu general public license as published by
# the free software foundation; either version 2 of the license, or
# (at your option) any later version.
#
# this program is distributed in the hope that it will be useful,
# but without any warranty; without even the implied warranty of
# merchantability or fitness for a particular purpose.  see the
# gnu general public license for more details.
#
# you should have received a copy of the gnu general public license
# along with this program; if not, write to the free software
# foundation, inc., 51 franklin st, fifth floor, boston, ma  02110-1301  usa

# USAGE:
#./airtime.py -f <pcap-file> -i <interval> -w <filter> -o <output_format> [--no-fcs]

#Options:
# -h, --help            show this help message and exit
# -f PCAPFILE, --pcap-file=PCAPFILE
#                       Capture dump
# -t TEXTFILE, --text-file=TEXTFILE
#                       Capture already converted/filtered
# -i INTERVAL, --interval=INTERVAL
#                       Consolidation interval in seconds
# -w FILTER, --filter=FILTER
#                       Wireshark filter
# -o OUTPUT, --output-format=OUTPUT
#                       Output Format [csv, lines]
# --no-fcs              don't check if frames have bad crc
#


import sys
import commands
import math
from optparse import OptionParser

arguments = OptionParser()
arguments.add_option("-f","--pcap-file",
                     dest="pcapfile",
                     help="Capture dump")
arguments.add_option("-t","--text-file",
                     dest="textfile",
                     help="Capture already converted/filtered")
arguments.add_option("-i","--interval",
                     dest="interval",
                     help="Consolidation interval in seconds")
arguments.add_option("-w","--filter",
                     dest="filter",
					 default="",
                     help="Wireshark filter")
arguments.add_option("-o","--output-format",
                     dest="output",
                     help="Output Format [csv, lines] ")
arguments.add_option("--no-fcs",
                     action="store_false",
                     dest="crc",
                     default=True,
                     help="don't check if frames have bad crc")
(options, args) = arguments.parse_args()

if not (options.pcapfile or options.textfile) :
   print "input file is mandatory"
   sys.exit(0)
filter_exp = ''
filter = ''
if options.crc == True:
   filter += 'wlan.fcs_good == 1'
   if options.filter:
      filter += ' and '+options.filter
else:
   filter += options.filter
if options.crc or options.filter:
   filter_exp = '-R "'+filter+'"'
if options.pcapfile:
   pcapfile = options.pcapfile
   inputfile = pcapfile
if options.textfile:
   textfile = options.textfile
   inputfile = textfile
else:
   textfile = pcapfile+'.tmp3'
   filter_cmd='tshark -r %s %s -T fields -e frame.time_relative -e radiotap.datarate -e frame.len -e radiotap.channel.type.cck -e radiotap.channel.type.dynamic -e radiotap.channel.type.ofdm -e radiotap.flags.preamble -e radiotap.channel.type.2ghz -e radiotap.channel.type.5ghz > %s' % (pcapfile, filter_exp, textfile)
#   print "filter: '%s'" % filter_cmd
   s, o = commands.getstatusoutput(filter_cmd)
if options.interval:
   interval = float(options.interval)
else:
   interval = 1
timeslot = 0
lastslot = 0
airtime = [0]


fd = open(textfile, 'r')

#cck_datarates = ('2', '4', '11', '22')
#ofdm_datarates = ('12', '18', '24', '36', '48', '72', '96', '108')

cck_datarates = ('1', '2', '5.5', '11')
ofdm_datarates = ('6', '9', '12', '18', '24', '36', '48', '54')

lno = 0
for line in fd:
	lno += 1
	time, rate, size, cck, dynamic, ofdm, preamble, twoghz, fiveghz = line.replace("\n", "").split('\t')
	size = size.strip('\n')

	### ARITIME calculation ###

	# 802.11b (DSSS-CCK TXTIME calculations)
	# TXTIME = PreambleLength + PLCPHeaderTime + Ceiling(((LENGTH+PBCC) × 8) / DATARATE)
	if ( rate in cck_datarates ):
		if ( preamble == '1' ): #short preamble
			airsize = 72 + 24 + math.ceil( float(size) * 8 / float(rate) )
		else:					#long preamble
			airsize = 144 + 48 + math.ceil( float(size) * 8 / float(rate) )
	elif ( rate in ofdm_datarates ):
		# 802.11a (OFDM TXTIME calculation)
		# TXTIME = TPREAMBLE + TSIGNAL + TSYM × Ceiling((16 + 8 × LENGTH + 6)/NDBPS)
		if ( ofdm == '1' and fiveghz == '1' ):
			airsize = 16 + 4 + 4* math.ceil( (16 + float(size) * 8 + 6) / (4 * float(rate)) )
		# 802.11g-only (ERP-OFDM TXTIME calculations)
		# TXTIME = TPREAMBLE + TSIGNAL + TSYM × Ceiling ((16 + 8 × LENGTH + 6)/NDBPS) + Signal Extension
		elif ( ofdm == '1' and twoghz == '1' ):
			airsize = 16 + 4 + 4* math.ceil( (16 + float(size) * 8 + 6) / (4 * float(rate)) ) + 6
		# 802.11g mixed (DSSS-OFDM TXTIME calculations)
		# TXTIME = PreambleLengthDSSS + PLCPHeaderTimeDSSS + PreambleLengthOFDM + PLCPSignalOFDM +
		#   4 × Ceiling((PLCPServiceBits + 8 × (NumberOfOctets) + PadBits) / NDBPS) + SignalExtension
		elif ( dynamic == '1' and twoghz == '1' ):
			if ( preamble == '1' ): #short preamble
				airsize = 72 + 24 + 8 + 4 + 4* math.ceil( (16 + float(size) * 8 + 6) / (4 * float(rate)) ) + 6
			else:                   #long preamble
				airsize = 144 + 48 + 8 + 4 + 4* math.ceil( (16 + float(size) * 8 + 6) / (4* float(rate)) ) + 6
		else:
			airsize = 0
	else:
		airsize = 0

	timeslot = int(math.floor(float(time) / interval))
	if timeslot > lastslot:
		for slot in range(lastslot, timeslot): 
			airtime.append(0)

	try:
		airtime[timeslot] += airsize / (interval * 1000000)
	except:
		print "failed at line %d: %s" % (lno, line)
	lastslot = timeslot

if options.output == "csv":
	for i in airtime:
		print str(i)+',',
else:
	for i in range(0, len(airtime)):
		print "%s;%.2f" % (i*interval, airtime[i] * 100)

