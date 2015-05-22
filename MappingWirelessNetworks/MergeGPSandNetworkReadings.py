# MERGE GPS AND NETWORK READINGS
# Jeff Thompson | 2013 | www.jeffreythompson.org
#
# Merges wireless network data and GPS readings by correlating
# date/time.

# year-month-date_hour:min:sec

# assumes 8-hour diff to EST

import re
import time
from datetime import datetime, timedelta


timeDiff = timedelta(seconds=(3600 * 8))	# difference between GPS and wireless time in hours

wirelessFile = "OutputData/DetroitMichigan_Feb15-2013/DetroitNetworks_Raw.txt"
gpsFile = "OutputData/DetroitMichigan_Feb15-2013/DetroitGPS.gpx"

networkData = []		# raw network data
networkTime = []		# network data times
gpsLocation = []		# just gps locations (lat/lon)
gpsTime = []			# separate list of times

# gather wireless data into list
# 2013-02-15,11-56-11
wireless = open(wirelessFile)
for reading in wireless:
	reading = re.sub('\n|\t|\r', '', reading)
	t = re.findall('(\d+-\d+-\d+,\d+-\d+-\d)', reading)
	if len(reading) > 0 and len(t) > 0:
		networkData.append(reading)
		t = datetime.strptime(t[0], "%Y-%m-%d,%H-%M-%S")
		networkTime.append(t)
wireless.close()

print '# network entires:     ' + str(len(networkData))
print '# network dates/times: ' + str(len(networkTime))

# gather and clean up gps data
# <time>2013-02-15T19:00:53Z</time>
rawGPS = open(gpsFile)
for reading in rawGPS:
	reading = re.sub('\n|\t|\r', '', reading)
	if 'trkpt' in reading:
		lat = re.findall('lat="(.*?)"', reading)
		lon = re.findall('lon="(.*?)"', reading)
		if len(lat) > 0 and len(lon) > 0:
			gpsLocation.append(lat[0] + ',' + lon[0])		
		
	elif '<time>' in reading:		
		time = re.findall('<time>(.*?)</time>', reading)
		if len(time[0]) > 0:	
			time = re.sub('T', '_', time[0])
			time = re.sub('Z', '', time)			
			t = datetime.strptime(time, "%Y-%m-%d_%H:%M:%S")	# 2013-02-15_19:07:34
			t -= timeDiff
			gpsTime.append(t)
rawGPS.close()

# create list of GPS times as total # of seconds
# use this to compare to network times to find location - only works
# because we know our dates to all be the same
gpsSec = []
for t in gpsTime:
	sec = (t.hour * 3600) + (t.minute * 60) + t.second
	gpsSec.append(sec)


print '# GPS locations:       ' + str(len(gpsLocation))
print '# GPS dates/times:     ' + str(len(gpsTime))

# find closest time and append to wireless data
# http://stackoverflow.com/questions/12141150/from-list-of-integers-get-number-closest-to-some-value
index = 0
for network in networkData:
	timeInSec = (networkTime[index].hour * 3600) + (networkTime[index].minute * 60) + networkTime[index].second
	closest = min(gpsSec, key=lambda i : abs(i-timeInSec))
	gpsIndex = gpsSec.index(closest)
	networkData[index] += ',' + gpsLocation[gpsIndex]
	index += 1

for i in range(0,len(gpsLocation)):
	print str(gpsLocation[i]) + " : " + str(gpsTime[i]) + " : " + str(gpsSec[i])

print ""

for s in networkData:
	print s
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	