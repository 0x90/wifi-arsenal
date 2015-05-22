#!/usr/bin/env python
# ----------------------------------------------
# Junaid Loonat (junaid@sensepost.com)
# JStripper - Parser for modified SSLStrip logs
# ----------------------------------------------
# How to import a CSV into a MySQL database:
#	http://www.tech-recipes.com/rx/2345/import_csv_file_directly_into_mysql/
# ----------------------------------------------

import os
import sys
import time
import base64
import urllib
import csv
import re

def usage():
	print 'Usage: jstripper.py file'

def processEntry(entry):
	print 'processEntry %s' % entry
	exportFile.writerow([
		entry['timestamp'],
		entry['src_ip'],
		entry['domain'],
		entry['url'],
		entry['secure'],
		entry['post']
	])

if __name__ == '__main__':
	if len(sys.argv) != 2:
		usage()
		sys.exit()
	logFilePath = sys.argv[1]
	if not os.path.exists(logFilePath):
		print 'Specified log file does not exist: %s' % logFilePath
	elif not os.path.isfile(logFilePath):
		print 'Specified log file does not appear to be a file: %s' % logFilePath
	else:
		exportFilePath = '%s%s' % (logFilePath, '.export')
		print 'Export file will be: %s' % exportFilePath
		if os.path.exists(exportFilePath):
			print 'Removing existing export file: %s' % exportFilePath
			os.remove(exportFilePath)
		exportFile = csv.writer(open(exportFilePath, 'wb'), delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
		exportFile.writerow(['timestamp', 'src_ip', 'domain', 'url', 'secure', 'post'])

		logFile = open(logFilePath, 'r')
		isEntry = False
		anEntry = {}
		for aLine in logFile:
			if aLine.startswith('2012-') and aLine.find(' Client:') > -1:
				if isEntry:
					processEntry(anEntry)
					isEntry = False
				
				if aLine.find(' POST Data (') > -1:
					isEntry = True
					anEntry = {}
					anEntry['timestamp'] = aLine[:aLine.find(',')]
					anEntry['secure'] = 0
					anEntry['post'] = ''
					if aLine.find('SECURE POST Data (') > -1:
						anEntry['secure'] = 1
						
					tStart = aLine.find(' POST Data (') + 12
					anEntry['domain'] = aLine[tStart:aLine.find(')', tStart)]
					
					tStart = aLine.find(' Client:') + 8
					anEntry['src_ip'] = aLine[tStart:aLine.find(' ', tStart)]
					
					tStart = aLine.find(' URL(') + 8
					anEntry['url'] = aLine[tStart:aLine.find(')URL', tStart)]
					
			elif isEntry:
				anEntry['post'] = '%s%s' % (anEntry['post'], urllib.unquote_plus(aLine.strip()))
				
		if isEntry:
			processEntry(anEntry)
			
		
		logFile.close()
	
		
		
		
		print 'done'
