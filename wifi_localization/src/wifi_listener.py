#!/usr/bin/env python

import roslib; roslib.load_manifest('wifi_lookup')
import rospy, pickle, sys
from wifi_lookup.msg import WifiData, Wifi

#1st goal, Completed, create a method to build a database which
#	is shared between different instances of the node
#2nd goal, Completed, redefine the database to perform the
#	two-dimensional hash lookup
#3rd goal, Completed, modify the listener for x,y injection;
#	location injection checks to prevent duplicates

#This is the file which is loaded/stored
dbLoc = "database.pk"

#This is a default location until the prompting works
#injectLoc = (0,0)

#The layers of temps and resetting are there for safe
def inject(data):
	for spot in data.HotSpots:
		print spot.MAC, spot.dB
		if spot.MAC in database:
			firstTemp = database[spot.MAC]
		else:
			firstTemp = {}
		if spot.dB in firstTemp:
			secondTemp = firstTemp[spot.dB]
		else:
			secondTemp = []
		if(not injectLoc in secondTemp):
			secondTemp.append(injectLoc)
		firstTemp[spot.dB] = secondTemp
		database[spot.MAC] = firstTemp
	
#serialize the data for storage
def clean():
	dbFile = open(dbLoc,"w")
	pickle.dump(database, dbFile)
	dbFile.close()

#deserialize the object and do ROS things
def make():
	global database
	global injectLoc
	try:
		dbFile = open(dbLoc)
		database = pickle.load(dbFile)
		dbFile.close()
	except: 
		database = {}
	injectLoc = (int(sys.argv[1]), int(sys.argv[2]))
	print injectLoc
	rospy.Subscriber('wifi_data', WifiData, inject)
	rospy.spin()

if __name__=='__main__':
	rospy.init_node('wifi_listener')
	try:
		make()
	except rospy.ROSInterruptException: pass
	clean()
