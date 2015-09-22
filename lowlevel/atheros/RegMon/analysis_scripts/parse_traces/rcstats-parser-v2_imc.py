#!/usr/bin/env python                                                                                                                                                                                                                        

import sys, os, psycopg2
from time import sleep,time
import os
import subprocess
from optparse import OptionParser
from threading import *
from progress import ProgressBar
import re

getopt = OptionParser()
getopt.add_option('-i', '--inputfile', dest='inputfile', help='measurement file', default='')
getopt.add_option('-o', '--outputfile', dest='outputfile', help='output file for reformatted CSV output', default='default.csv')
(sopts, sargs) = getopt.parse_args()

# fix directories
if (not os.path.exists(sopts.inputfile)):
	print "error: file %s does not exist" % sopts.inputfile
	sys.exit(255)
	
# global variables
main_loop = True

## file handler thread
#class ParserThread(Thread):
#
#	def __init__(self, file_in, file_out):
#		Thread.__init__(self)
#		self.__filein = file_in
#		self.__fileout = file_out
#
#	def get_num_lines(self, fname):
#		try:
#			out = subprocess.check_output(['wc', '-l', fname])
#			return int(out.split(" ")[0])
#		except:
#			return -1
#
#	def countfields(self, line):
#		cbf = len(line)
#		caf = len(line.replace(",", ""))
#		return cbf - caf
#
#	def run(self):
#		self.__loop = True
#		self.__neighbor = ""
#		lc = 0
#		# open input+output file
#		fh = open(self.__filein, 'r')
#		fhout = open(self.__fileout, 'w')	# rewrite
#		fhout.write("timestamp,neighbor,capabilities,mrr_T,mrr_t,mrr_P,rate,throughput,ewma_prob,this_prob,this_succ,this_attempt,success,attempts\n")
#		linebuffer = []
#		headers = False
#		t0 = time()
#		print "getting length of file... ",
#		numlines = self.get_num_lines(self.__filein)
#		if (numlines > -1):
#			print "%d lines" % numlines
##			self.progress = ProgressBar(50)
##			self.progress.show(0)
#		else:
#			print "failed"
#
#		while (self.__loop):
#			filepos = fh.tell()	# remember position before reading
#			line = fh.readline()
#			if ((not "\n" in line) and (line != '')):
#				fh.seek(filepos)
#				self.rest()
#			else:
#				if (line != ''):
#					lc += 1
#					if (lc % 10000 == 0 and numlines > -1):
#						duration = (time() - t0)
#						t0 = time()
#						print "%5.1f" % (lc / numlines * 100)
##						self.progress.show(lc / numlines * 100)
#
#				if (line == ''):
#					self.__loop = False
#				skipline = False
#				if ('neighbor' in line):
#					# neighbor annotation detected
#					neighbor = line.replace("\n", "").replace("neighbor: ", "").replace(" ", "")
#					self.__neighbor = neighbor
#					
#					# flush linebuffer to output and empty it
#					for lout in linebuffer:
#						fhout.write("%s\n" % lout)
#					linebuffer = []
#
#				elif (line != ''):
#					# test if we have a line containing values
#					fields = line.replace("\n", "").split(',')
#					fcount = self.countfields(line)
#					if ('timestamp' in line or (fcount < 9)):
#						skipline = True
#					try:
#						# OK, write to output
#						value_ts = float(fields[0])
#					except:
#						# FAIL, no timestamp
#						skipline = True
#
#					if (not skipline):
#						value_ts = float(fields[0])
#						line_legacy = (fcount == 9)
#						value_neigh = self.__neighbor
#						if (line_legacy):
#							value_cap = "legacy"
#							value_mrr = ",".join(fields[1]).replace(" ", "")
#							value_remain = ",".join(fields[2:])
#						else:	
#							value_cap = fields[1]
#							value_mrr = ",".join(fields[2]).replace(" ", "")
#							value_remain = ",".join(fields[3:])
#
#						lout = "%s,%s,%s,%s,%s" % (value_ts, value_neigh, value_cap, value_mrr, value_remain)
#						lout = lout.replace(" ", "")
#						linebuffer.append(lout)
#
#		# flush linebuffer to output and empty it
#		for lout in linebuffer:
#			fhout.write("%s\n" % lout)
#		linebuffer = []
#
#		# close and exit
#		fh.close()
#		fhout.close()
#		self.progress.disable()

def get_num_lines(fname):
	try:
		out = subprocess.check_output(['wc', '-l', fname])
		return int(out.split(" ")[0])
	except:
		return -1

def get_num_fields(line):
	cbf = len(line)
	caf = len(line.replace(",", ""))
	return cbf - caf


print "parsing file '%s'" % sopts.inputfile
neighbor = ""
lc = 0

# open input+output file
fh = open(sopts.inputfile, 'r')
fhout = open(sopts.outputfile, 'w')	# rewrite
fhout.write("timestamp,neighbor,capabilities,mrr_T,mrr_t,mrr_P,rate,throughput,ewma_prob,this_prob,this_succ,this_attempt,success,attempts\n")
linebuffer = []
headers = False
t0 = time()
print "getting length of file... ",
numlines = get_num_lines(sopts.inputfile)
if (numlines > -1):
	print "%d lines" % numlines
	progress = ProgressBar(50)
	progress.show(0)
else:
	print "failed"

while (main_loop):
	try:
		filepos = fh.tell()	# remember position before reading
		line = fh.readline()
		if ((not "\n" in line) and (line != '')):
			fh.seek(filepos)
		else:
			if (line != ''):
				lc += 1
				if (lc % 10000 == 0 and numlines > -1):
					duration = (time() - t0)
					t0 = time()
					perc = (lc * 1.0 / numlines) * 100.0
#					print "%5.1f, %d" % (perc, lc)
					progress.show(perc)

			if (line == ''):
				main_loop = False
			skipline = False
			if ('neighbor' in line):
				# neighbor annotation detected
				neighbor = line.replace("\n", "").replace("neighbor: ", "").replace(" ", "")
				
				# flush linebuffer to output and empty it
				for lout in linebuffer:
					fhout.write("%s\n" % lout)
				linebuffer = []

			elif (line != ''):
				# test if we have a line containing values
				fields = line.replace("\n", "").split(',')
				fcount = get_num_fields(line)
				if ('timestamp' in line or (fcount < 9)):
					skipline = True
				try:
					# OK, write to output
					value_ts = float(fields[0])
				except:
					# FAIL, no timestamp
					skipline = True

				if (not skipline):
					value_ts = float(fields[0])
					line_legacy = (fcount == 9)
					value_neigh = neighbor
					if (line_legacy):
						value_cap = "legacy"
						value_mrr = ",".join(fields[1]).replace(" ", "")
						value_remain = ",".join(fields[2:])
					else:	
						value_cap = fields[1]
						value_mrr = ",".join(fields[2]).replace(" ", "")
						value_remain = ",".join(fields[3:])

					lout = "%s,%s,%s,%s,%s" % (value_ts, value_neigh, value_cap, value_mrr, value_remain)
					lout = lout.replace(" ", "")
					linebuffer.append(lout)
	except:
		main_loop = False

# flush linebuffer to output and empty it
for lout in linebuffer:
	fhout.write("%s\n" % lout)
linebuffer = []

# close and exit
fh.close()
fhout.close()
progress.disable()

print "done :)"
