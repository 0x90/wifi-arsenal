#!/usr/bin/env python

# kismet2earth 1.0
# Author: Andrea Grandi <a.grandi AT gmail com>
# License: GPL2
# Copyright: Andrea Grandi 2010 - This code is partially based on PyKismetKml (http://code.google.com/p/pykismetkml)

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import sqlite3
import optionparser

def iconify(encryption):
    icon = "<Style><IconStyle><Icon>"
    
    if encryption == 'WPA':
        icon += "<href>images/node_wpa.png</href>"
    elif encryption == 'WEP':
        icon += "<href>images/node_wep.png</href>"
    else:
        icon += "<href>images/node_open.png</href>"
    return icon + "</Icon></IconStyle></Style>"

def export_wifi(rows, filename):
    f = open(filename, 'wt')
    
    f.write("""<?xml version='1.0' encoding='UTF-8'?>
            <kml xmlns='http://earth.google.com/kml/2.0'>
            <Folder><name>Wifi Networks</name>""")
    
    fullstr = ""
    
    for row in rows:
        bssid = row[0]
        essid = row[1]
        lat = row[2]
        lon = row[3]
        encryption = row[4]
        manufacturer = row[5]
        channel = row[6]
        
        icon = iconify(encryption)
        
        fullstr += """<Folder>
                                <name>%s</name>
                            
                                    <LookAt>
                                        <longitude>%s</longitude>
                                        <latitude>%s</latitude>
                                        <range>100</range>
                                        <tilt>54</tilt>
                                        <heading>-35</heading>
                                    </LookAt>
                            
                            <description></description>
                                <Placemark>
                                    <name>%s</name>
                                    <description><![CDATA[
                                            BSSID: %s<br>
                                            Manufacturer: %s<br>
                                            Channel: %s<br>
                                            Encryption: %s<br>
                                            ]]></description>
                                    <visibility>1</visibility>
                                    <open>0</open>
                                    
                                    <LookAt>
                                        <longitude>%s</longitude>
                                        <latitude>%s</latitude>
                                        <range>100</range>
                                        <tilt>54</tilt>
                                        <heading>-35</heading>
                                    </LookAt>
                                                       
                                    %s
                                    
                                    <Point>
                                        <altitudeMode>clampedToGround</altitudeMode>
                                        <extrude>0</extrude>
                                        <tessellate>0</tessellate>
                                        <coordinates>%s,%s,0</coordinates>
                                    </Point>
                                </Placemark>
                            </Folder>\n\n\n""" % (essid, lon, lat, essid, bssid, manufacturer, channel, encryption, lon, lat, icon, lon, lat)
                            
    f.write(fullstr)
    f.write("</Folder></kml>")
    f.close()

def read_wifi(db, options):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    
    where = ""
    sql = ""
    
    if options.all == True:
        sql = "SELECT * FROM networks"
    else:
        if options.wpa == True:
            if where == "":
                where += " WHERE encryption = 'WPA'"
            else:
                where += " OR encryption = 'WPA'"
        if options.wep == True:
            if where == "":
                where += " WHERE encryption = 'WEP'"
            else:
                where += " OR encryption = 'WEP'"
        if options.open == True:
            if where == "":
                where += " WHERE encryption = 'Open'"
            else:
                where += " OR encryption = 'Open'"
        
        sql = "SELECT * FROM networks" + where
    
    c.execute(sql)
    
    rows = []
    
    for row in c:
        rows.append(row)
        
    c.close()
        
    return rows

parser = optionparser.OptionParser()
parser.add_option("-i", "--input", dest="database", help="Path to Sqlite3 database.")
parser.add_option("-o", "--output", dest="filename", help="Path to .kml output file.")
parser.add_option("-w", "--wpa", action = "store_true", dest="wpa", default=False, help="Export WPA encrypted networks.")
parser.add_option("-p", "--wep", action = "store_true", dest="wep", default=False, help="Export WEP encrypted networks.")
parser.add_option("-n", "--open", action = "store_true", dest="open", default=False, help="Export Open networks.")
parser.add_option("-a", "--all", action = "store_true", dest="all", default=False, help="Export all networks.")
(options, args) = parser.parse_args()

rows = read_wifi(options.database, options)
export_wifi(rows, options.filename)