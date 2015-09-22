#!/usr/bin/env python


import sys, os
import pprint
import numpy as np
from optparse import OptionParser

getopt = OptionParser()
getopt.add_option('-d', '--inputdelimiter', dest='inputsep', help='specify the input delimiter used in trace files', default="\t")
getopt.add_option('-D', '--outputdelimiter', dest='outputsep', help='specify the output delimiter for merged traces', default="\t")
getopt.add_option('-H', '--headers', dest='headers', help='file has headers', action='store_true', default=False)
getopt.add_option('-c', '--column', dest='column', help='column of interest', default=2)
getopt.add_option('-w', '--window', dest='window', help='moving average time window', default=1)
getopt.add_option('-o', '--output', dest='output', help='output file name', default="result")
getopt.add_option('-t', '--timestamp', dest='timestamp', help='index of timestamp column', default=1)
getopt.add_option('-u', '--undefined', dest='undefined', help='string that is filled into undefined cells', default="")
getopt.add_option('-b', '--boundaries', dest='bounds', help='comma separated boundaries for values: min,max, "-" for undefined', default="-,-")
#getopt.add_option('-v', '--verbosity', action='count', dest='verbosity', help='set verbosity level', default=1)
(sopts, sargs) = getopt.parse_args()


def print_err(msg):
	print >>sys.stderr, "Error: %s" % msg


def near(a, b, eps = 0.0000001):
	"""
	returns whether numerical values a and b are within a specific epsilon environment
	"""
	diff = abs(a-b)
	return diff < eps

# check if files are specified
try:
	fname = sys.argv[-1]
	if (not os.path.isfile(fname) or len(sys.argv) <= 1):
			raise Exception("")
except:
	getopt.print_help()
	sys.exit(-1)

bounds = {}

if (not ',' in sopts.bounds):
	print_err("bounds must be specifed as 'min,max'");
	sys.exit(1);

tmpbounds = sopts.bounds.split(',')
if ('-' != tmpbounds[0]):
	bounds['min'] = float(tmpbounds[0])
if ('-' != tmpbounds[1]):
	bounds['max'] = float(tmpbounds[1])

fh = open(fname,"r")

inputsep = str(sopts.inputsep)
outputsep = str(sopts.outputsep)
windowsize = 0
try:
	windowsize = float(sopts.window)
	sopts.column = int(sopts.column)
	sopts.timestamp = int(sopts.timestamp)
except:
	pass

lf = fh.readline()
if (sopts.headers):
	lf = fh.readline()

windowcount = 0 
fh_counter = open("%s-counter.csv" % sopts.output, "w")
mdata = {'values' : []}

# write header colums

def shift_window(ma, window, currentts):
	global windowcount
	shiftcount = 0
	while (ma['from'] <= currentts):
		ma['from'] += window
		windowcount += 1
		shiftcount += 1
	ma['to'] = ma['from']
	ma['from'] -= window
	windowcount -= 1
	res = shiftcount > 1
	return res	# shifted?	

while (lf != ""):
	
	values = lf.replace("\n", "").split(inputsep)
	if (len(values) == 1):
		lf = fh.readline()
		continue
	try:
		currentval = float(values[sopts.column-1])
	except:
		lf = fh.readline()
		continue
	if (currentval == sopts.undefined):
		lf = fh.readline()
		continue
	if ((bounds.has_key('min') and currentval < bounds['min']) or (bounds.has_key('max') and currentval > bounds['max'])):
		lf = fh.readline()
		continue

	ts = float(values[sopts.timestamp-1])

	if (not mdata.has_key('from')):	# start of first time window for moving average
		mdata['from'] = ts
		mdata['to'] = mdata['from'] + windowsize

	if (shift_window(mdata, windowsize, ts)):
		scnt = sum(mdata['values'])
#		print "window: %d values: %d" % (windowcount, len(mdata['values']))
		fh_counter.write("%d%s%f\n" % (windowcount, outputsep, scnt))
		mdata['values'] = []

	if (currentval >= 0):
		mdata['values'].append(currentval)

	lf = fh.readline()

if (len(mdata['values']) > 0):
	windowcount += 1
	scnt = sum(mdata['values'])
	fh_counter.write("%d%s%f\n" % (windowcount, outputsep, scnt))

fh_counter.close()
fh.close()
