#!/usr/bin/env python
import xml.etree.ElementTree as ET
import sys

#Check if number of arguments is correct, otherwise print usage
if len(sys.argv) != 4:
    print "Usage: %s <Kismet.netxml File> <Mode> <Output File Name>" % sys.argv[0]
    print "Example: %s /root/Kismet-20140725-22-33-53-1.netxml -wep wep_networks.csv" % sys.argv[0]
    print "Example will parse the provided .netxml file and output a csv file of WEP networks for upload to Google Maps Engine" 
    print "\nModes: -open or -wep \n"
    sys.exit(1)

#Move arguments for Nessus directory and output file prefix to variables
netxml = sys.argv[1]
mode = sys.argv[2]
filename = str(sys.argv[3])
tree = ET.parse(netxml)
root = tree.getroot()

print "Kismet Scan Performed on: " + root.attrib['start-time'] + "\n\n"
outfile = open(filename,"w")

outfile.write("name,lat,lon")

for child in root:
    if child.tag == "wireless-network":
        wap = child
        encryption = ""
        bssid = ""
        essid = ""
        peak_lon = ""
        peak_lat = ""
        for element in wap:
	    if element.tag == "SSID":
                for x in element:
                    if x.tag == "encryption":
                        encryption = str(x.text)
                    elif x.tag == "essid":
                        essid = str(x.text)
            elif element.tag == "BSSID":
                bssid = str(element.text)
            elif element.tag == "gps-info":
                for x in element:
                    if x.tag == "peak-lat":
                        peak_lat = str(x.text)
                    elif x.tag == "peak-lon":
                        peak_lon = str(x.text)
        if essid != "" and essid != "None":
            if mode == "-wep":
                if encryption == "WEP":    
                    print essid + "\t" + bssid + "\t" + encryption
                    outfile.write("\n"+essid+","+peak_lat+","+peak_lon)
                else:
                    pass
            if mode == "-open":
                if encryption == "None":
                    print essid + "\t" + bssid + "\t" + encryption
                    outfile.write("\n"+essid+","+peak_lat+","+peak_lon)
                else:
                    pass
outfile.close()
