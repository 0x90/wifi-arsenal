#!/usr/bin/python

import sys
import os


menuInput = "dummy"

def printHelpMenu():
	print ""
	print "Usage: " + sys.argv[0] + " <INTERFACE> <OPTION> <OPTION_PARAMETER>"
	print "Available options:"
	print "-a: scan for accesspoints"
	print "-b: beacon flood mode"
	print "-h: show this help menu"
	print "-m: start monitormode (airmon-ng required)"
	print "-p: scan for probe requests"
	print "-w: wizzard"
	print ""
	sys.exit()


if len(sys.argv) < 2:
	# print help menu
	printHelpMenu()
else:
	if len(sys.argv) < 3:
		if sys.argv[2] != "-w":
			print "Missing option!"
			printHelpMenu()
	
	chosenOption = sys.argv[2]
	
	if chosenOption != "-w":
		interface = sys.argv[1]
		location = sys.argv[4]
		numberOfPackets = sys.argv[3]
	else:
		interface = "null"
		location = "null"
		numberOfPackets = "null"

	# call the help menu
	if chosenOption == "-h":
		printHelpMenu()
	# call the "scan for accesspoint" script
	elif chosenOption == "-a":
		print "Scanning for accesspoints now..."
		os.system("./scanForAps.py " + interface + " " + numberOfPackets + " " + location)
	# beacon flood mode
	elif chosenOption == "-b":
		print "Sending random beacon frames..."
		os.system("./beaconFlood.py " + interface + " " + numberOfPackets)
	# start monitor mode
	elif chosenOption == "-m":
		print "Starting monitor mode now..."
                os.system("airmon-ng start " + interface)
	# call the "scan for probe requests" script
	elif chosenOption == "-p":
		print "Scanning for probe requests now..."
		os.system("./clientProbes.py " + interface + " " + numberOfPackets + " " + location)
	# call the wizzard
	elif chosenOption == "-w":
		while menuInput != 99:
			print ""
			print "Which script do you want to execute?"
			print "1.  Scan for accesspoints."
			print "2.  Beacon flood mode"
			print "3.  Scan for client probe requests."
			print "99. Exit wizzard."
			try:
				menuInput = int(raw_input("Selection: "))
				# scan for accesspoints
				if menuInput == 1:
					wizzardInterface = raw_input("Listening interface: ")
					numberOfPackets = raw_input("Number of packets to sniff: ")
					location = raw_input("Your current location: ")
					os.system("./scanForAps.py " + wizzardInterface + " " + numberOfPackets + " " + location)
				# beacon flood mode
				if menuInput == 2:
					wizzardInterface = raw_input("Listening interface: ")
                                        numberOfPackets = raw_input("Number of packets to sniff: ")
					os.system("./beaconFlood.py " + wizzardInterface + " " + numberOfPackets)
				# scan for clientprobes
				if menuInput == 3:
					wizzardInterface = raw_input("Listening interface: ")
					numberOfPackets = raw_input("Number of packets to sniff: ")
					location = raw_input("Your current location: ")
					os.system("./clientProbes.py " + wizzardInterface + " " + numberOfPackets + " " + location)
			except Exception, e:
				print "Wrong input!"
	# no valid option entered
	else:
		print "Wrong option!"
		printHelpMenu()
