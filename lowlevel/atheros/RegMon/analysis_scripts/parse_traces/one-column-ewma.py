#!/usr/bin/env python2.7


import sys, os
import pprint
import numpy as np
from optparse import OptionParser

getopt = OptionParser()
getopt.add_option('-d', '--inputdelimiter', dest='inputsep', help='specify the input delimiter used in trace files', default="\t")
getopt.add_option('-D', '--outputdelimiter', dest='outputsep', help='specify the output delimiter for merged traces', default="\t")
getopt.add_option('-H', '--headers', dest='headers', help='file has headers', action='store_true', default=False)
getopt.add_option('-c', '--column', dest='column', help='column of interest', default=2)
#getopt.add_option('-w', '--window', dest='window', help='moving average time window', default=1)
getopt.add_option('-a', '--alpha', dest='alpha', help='exponential moving average with alpha', default=0.4)
getopt.add_option('-o', '--output', dest='output', help='output file name', default="result")
getopt.add_option('-t', '--timestamp', dest='timestamp', help='index of timestamp column', default=1)
getopt.add_option('-u', '--undefined', dest='undefined', help='string that is filled into undefined cells', default="")
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

fh = open(fname,"r")

inputsep = str(sopts.inputsep)
outputsep = str(sopts.outputsep)
try:
	sopts.alpha = float(sopts.alpha)
	sopts.column = int(sopts.column)
	sopts.timestamp = int(sopts.timestamp)
except:
	pass
lf = fh.readline()
if (sopts.headers):
	lf = fh.readline()
fh_ewma = open("%s-ewma.csv" % sopts.output, "w")

#	0, -1
ewma = [0]
while (lf != ""):
	
	values = lf.replace("\n", "").split(inputsep)
	currentval = float(values[sopts.column-1])
	if (currentval == sopts.undefined):
		lf = fh.readline()
		continue

	if (len(ewma) < 2):
		ewma.insert(0, currentval)
	ewma.insert(0, currentval)
	ewma.pop()
	ts = float(values[sopts.timestamp-1])
	
	ewma[0] = sopts.alpha * currentval + (1 - sopts.alpha) * ewma[1]
	ewma[1] = ewma[0]
	fh_ewma.write("%f%s%f\n" % (ts, outputsep, ewma[0]))
	lf = fh.readline()

fh_ewma.close()
fh.close()
