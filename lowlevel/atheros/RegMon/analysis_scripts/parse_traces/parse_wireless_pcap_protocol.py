#!/usr/bin/env python2.6
#from sets import Set
import re
import optparse
import subprocess
from subprocess import Popen, PIPE
from optparse import OptionParser
import sys,os

getopt = OptionParser()
getopt.add_option('-i', '--interval', dest='interval', help='interval for time series output', default=100)
getopt.add_option('-o', '--output', dest='output', help='output file name', default="result")
(sopts, sargs) = getopt.parse_args()


import numpy as np
from numpy import *
#import scipy
#from scipy import * 
import matplotlib
matplotlib.use('WXAgg')
import matplotlib.pyplot as plt

#sumhead = ( 'a', 'b', 'c', 'd')
#sumarr = ( 3, 4, 5, 6)


#usage = "usage: %prog [options] arg1 arg2"
#parser = OptionParser(usage=usage)
#parser.add_option("-r", dest="filename", action="store", type="string", help="read pcap trace from FILE", metavar="FILE")
#parser.add_option("-w", dest="outfile", action="store", type="string", help="write report to FILE as csv", metavar="FILE")
#parser.add_option("-i", type="int", dest="interval", default=10, help="interval for output report statistics")
#results = parser.parse_args()
#print results.filename
#print results.outfile
#print interval
#exit
 
#options = parser.add_argument_group('options')
#options.add_argument("-q", "--quiet", action="store_false", dest="verbose", default=True, help="don't print status messages to stdout")

#(options, args) = parser.parse_args(args)
#results = parser.parse_args()

#os.path.dirname(outfile)


#sys.exit()
#try:
#	file = sys.argv[-1]
#	if (not os.path.isfile(fname) or len(sys.argv) <= 1):
#			raise Exception("")
#except:
#	getopt.print_help()
#	sys.exit(-1)
file = sys.argv[-1]
print file
#file = open(fname,"r")

#file="a-roof-1-tcpdump.pcap"
arr = []
parent = 0
tfilter= ''
sumhead = []
sumarr = []

#print "Will run now the tshark protocol hierarchy statistics"
trace = subprocess.Popen("tshark -q -r "+file+" -z io,phs | grep frames",shell=True, stdout=PIPE)

for line in trace.stdout.readlines():
	length = 0

#	if re.search("^\d",line):
	for proto in line.split('  '):
		proto = proto.strip()
		length += 1

		if len(proto) == 0:
			continue

		if re.search("^frames*",proto):
			value = proto.split(' ')
			frames = value[0].split(':')[1].strip()
			bytes = value[1].split(':')[1].strip()

#			bytes = bytes.strip()
#			sumarr.append(frames)
			sumarr.append(bytes)
			continue
		else:
			if parent >= length:
				del arr[length-1:len(arr)]
			parent = length
			arr.append(proto)
			sumhead.append('\"'+'.'.join(arr)+'.frames\"')
#			sumhead.append('\"'+'.'.join(arr)+'.bytes\"')
			tfilter += "("+'&&'.join(arr)+"),"
#			print summary
			continue
			#break

fout = open("%s-phssum.csv" % sopts.output, "w")
fout.write('\n'.join(','.join(x) for x in zip(sumhead, sumarr)))
fout.close()
# commented by Julius
#x = np.array(sumarr, int)
#tmphead = []
#tmparr = []
#
#for i, item in enumerate(sumhead):
##for i in sumarr:
#	if x[i] < (x[0]/200):
#		continue
#	tmphead.append(item)
#	tmparr.append(sumarr[i])
#	print item+"="+sumarr[i]
#
#for i, item in enumerate(tmphead):
#	print item+"="+tmparr[i]
#
#sumhead=tmphead
#sumarr=tmparr
#print "Will create plot"
#ind = np.arange(len(sumhead))
#width = 0.35
#x = np.array(sumarr, int)
#plt.plot(x.max(), len(sumhead), 'b^')
#
#plt.hlines(ind, 0, x, linewidth=2)
#plt.xlabel('byes (b)')
#plt.yticks(ind, sumhead )
#plt.title('Comparison of model with data')
##plt.legend( (sumhead[0], sumarr[0]), ('Men', 'Women') )
##for rect in ind:
##	plt.text(len(sumhead)*2-1, rect, sumhead[rect], ha='center', va='center')
##plt.xlim(xmin=0)
#plt.ylim(ymin=-1, ymax=len(sumhead))
#print "Will show plot now"
#plt.show()
#
##    for rect in rects:
##        height = rect.get_height()
##        plt.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%d'%int(height),
##                ha='center', va='bottom')
#exit()

#print "tshark -q -r "+file+" -z \""+tfilter+"\""

# This is the tshark filter for the second stage
tfilter = 'io,stat,'+str(sopts.interval)+','+arr[0]+'&&'+tfilter
atrace = subprocess.Popen("tshark -q -r "+file+" -z \""+tfilter+"\" -E header=y" ,shell=True, stdout=PIPE)

headline=0
header = []
header.append("timestamp")
fout = open("%s-phsall.csv" % sopts.output, "w")

for line in atrace.stdout.readlines():
#	if len(line) == 0:
#		line = "all"
	
	if re.search("^Column*",line):
		line = line.strip()
		line = re.sub('&&','_',line)
		line = re.sub('[\(\)]','',line)
		value = line.split(': ')
#		print value
		if len(value) == 2:
			header.append(value[1]+".frames")
			header.append(value[1]+".bytes")
		else:
			header.append("all.frames")
			header.append("all.bytes")
		headline=1
		continue
 	if re.search("^\s",line):
		if headline == 0:
			continue
		fout.write(','.join(header)+'\n')
		continue
	if re.search("^\d",line):
		line = line.strip()
		line = re.sub('-[0-9]+.[0-9]+','',line)
		line = re.sub('(\s+)',',',line)
		line = line.strip()
		fout.write(line+'\n')
		continue

fout.close()
