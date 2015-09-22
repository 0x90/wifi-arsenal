#!/usr/bin/env python


import sys

if (len(sys.argv) < 3):
	print "usage: %s <file 1> <file 2>" % sys.argv[0]	# argv[0] = script name
	sys.exit(0)

file1 = open(sys.argv[1],"r")
file2 = open(sys.argv[2],"r")


separator = "\t"

def print_row(t1, t2, col):
	global separator
	if (col == 1):
		helper = [''] * (len(t2)-1)
		print "%(ts)s%(sep)s%(list)s" % {'ts': t1[0], 'sep': separator, 'list': separator.join(t1[1:])+separator+separator.join(helper)}

	if (col == 2):
		helper = [''] * (len(t1)-1)
		print "%(ts)s%(sep)s%(list)s" % {'ts': t2[0], 'sep': separator, 'list': separator.join(helper)+separator+separator.join(t2[1:])}

	if (col == 3):
		print "%(ts)s%(sep)s%(list)s" % {'ts': t1[0], 'sep': separator, 'list': separator.join(t1[1:])+separator+separator.join(t2[1:])}

lf1 = file1.readline()
lf2 = file2.readline()

while (lf1 != "") or (lf2 != ""):

	if (lf1 != ""):
		tbl1 = lf1.split("\t")
		tbl1[-1] = tbl1[-1].replace("\n", "")
		ts1 = tbl1[0]
	if (lf2 != ""):
		tbl2 = lf2.split("\t")
		tbl2[-1] = tbl2[-1].replace("\n", "")
		ts2 = tbl2[0]

#	try:
	if (ts1 < ts2):
		col = 1
	elif (ts1 > ts2):
		col = 2
	else:
		col = 3
	if (lf1 == ""):
		col = 2
	if (lf2 == ""):
		col = 1

#	print "col=%(col)s ts1=%(ts1)s ts2=%(ts2)s tbl1=%(tbl1)s tbl2=%(tbl2)s" % {'col': col, 'ts1': ts1, 'ts2': ts2, 'tbl1' : ",".join(tbl1), 'tbl2': ",".join(tbl2)}
	print_row(tbl1, tbl2, col)			

#	except:
#		pass

	if (col in [1,3]):
		lf1 = file1.readline()
	if (col in [2,3]):
		lf2 = file2.readline()
file1.close()
file2.close()
