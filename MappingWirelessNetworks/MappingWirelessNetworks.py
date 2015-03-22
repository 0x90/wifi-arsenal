
'''
MAPPING WIRELESS NETWORKS
Jeff Thompson | 2013 | www.jeffreythompson.org

Get the names (and other details) of all wireless networks within reach and store
the results to a text file (named 'networks.txt')

DATA STORAGE FORMAT:
Data is stored in CSV format by default, with data in the following order:
	SSID, BSSID, RSSI, channel, HT, CC, security (auth/unicast/group), GPS coords if available, year-month-date, hh-mm-ss

WIRELESS NETWORK DATA - DETAILS:
While much of the wireless network data can likely be ignored, we store it just in case (and
it can be easily stripped or ignored later!).  Below are some details on the info gathered:

	SSID		Service Set Identifier, or the public name of the network
	BSSID		Basic Service Set Identification, generally the router's MAC address
	RSSI		Received Signal Strength Indicator, or the power of the wireless signal (range variable by manufacturer but generally ~ 0-100!)
	channel		like radio stations - in the US/Canada these are 1, 6, or 11
	HT			high-throughput? Appears to be Yes/No
	CC			possibly Country Code?  Appears to mostly list '--', but sometimes 'US'
	security	type of security for connecting (WPA is typical)
	auth		various and a bit complicated, see: http://bit.ly/VV75yh
	unicast		something about method/bandwidth for streaming, etc?
	group		?

METHODS and LIBRARIES:
Mac OS standard method (you may need to change this depending on your install:
	/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport -s

Or, you can create an alias to the 'airport' command by following these instructions (note, a
restart of Terminal might be required to have the alias work):
	http://www.macworld.com/article/1135392/airportterm.html#comment-form

Requires the PySerial module to talk to the Arduino (for GPS) over the USB connection:
	Info and download: 		http://pyserial.sourceforge.net
	Using with Arduino: 	http://playground.arduino.cc/interfacing/python

NOTES:
WarXing and WarDriving
http://en.wikipedia.org/wiki/WarXing and http://en.wikipedia.org/wiki/Wardriving#cite_note-8

'''

import subprocess			# for running Mac call to scan for networks
import re							# for matching IP addresses in longer string
import serial					# for talking to the Arduino (GPS)
import shlex					# for splitting text at spaces
import time						# get current date/time!

location = "TrainFromHobokenToGlenRidge"			# location (for filename
delimiter = ','													# what format to save the file (default is CSV)
spaceBetweenReadings = True							# separate readings with a space in text file?
getGPS = False													# connect to GPS Arduino shield
gpsConnected = False										# did we successfully connect to a GPS device?

outputFilename = "OutputData/" + location + "Networks_" + time.strftime("%Y-%m-%d_%H-%M-%S_raw") + ".txt"

# get current date and time from system
def getTime():
	t = time.strftime("%Y-%m-%d,%H-%M-%S")
	return t


# get all networks
def getNetworks():
	command = subprocess.Popen('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport -s', shell=True, stdout=subprocess.PIPE)
	networks = []												# save all networks to a list
	for line in command.stdout:									# if the line contains an IP address, parse and store
		if re.match('.*?:\d{1,3}:\d{1,3}', line) != None:		# IP test (something, then  series of 1-3 numbers with colon between)
			splitLine = shlex.split(line)						# split into list at spaces
			network = ""
			for i in range(len(splitLine)):						# iterate elements in line
				network += splitLine[i] + delimiter				# add element plus delimiter
			networks.append(network[0:-1])						# remove final delimimter
	return networks


# get GPS location from Arduino
def getGPS():
	if gpsConnected:
		coords = usb.readline()			# read data
		# parsing happens here! #
		return coords
	else:
		return ' '						# no GPS available, return blank



###
def main():

	# start GPS connection/baud rate - if failed, data-gathering will continue
	# without GPS data
	if getGPS:
		try:
			usb = serial.Serial('/dev/tty.usbserial', 9600)
			gpsConnected = True;
		except serial.serialutil.SerialException:
			print '\nERROR!'
			print '  No serial device (Arduino) connected!'
			print '  Data-gathering will continue without - to use GPS, please connect and restart this program.'
			print ''
	
	# once GPS connection is attempted, start collecting data!
	while 1:

		try:
		
			# get data to store
			print "Getting data..."
			networks = getNetworks()		# get all networks in range
			if getGPS:
				coordinates = getGPS()		# get GPS coords, if available
			currentTime = getTime()			# get current time
			
			# write the results to a text file!
			for network in networks:
				with open(outputFilename, 'a') as f:									# 'with' makes a 'close' statement unnecessary
					if getGPS:
						network += delimiter + coordinates + delimiter + currentTime	# combine into a single line, separated by delimiter
					else:
						network += delimiter + currentTime
					f.write(network + '\n')												# write to file with newline (inc here for better Terminal formatting)
				print '  ' + network													# print to window for monitoring/debugging
			print ' '																	# blank line between readings
			
			# if specified, put a blank line between readings (for easier separation and duplicate-removal)
			if spaceBetweenReadings:
				with open(outputFilename, 'a') as f:
					f.write('\n')
		except ValueError:
			continue

if __name__ == "__main__":
	main()