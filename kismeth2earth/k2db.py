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

import datetime, os, re, sys
import xml.dom.minidom
from xml.dom.minidom import Node
from xml.sax.saxutils import escape
import sqlite3
import optionparser

def ext_data(nodelist, tagname, index=0, branch=False):
    if branch:
        return nodelist.item(index).getElementsByTagName(tagname)
    else:
        try:
            return nodelist.item(index).getElementsByTagName(tagname).item(0).firstChild.data
        except AttributeError:
            if tagname == "essid":
                return "?Cloaked Network?"

def get_enc(nodelist):
    full = ''
    
    for each in nodelist:
        full += each.firstChild.data + " "
    if 'WPA' in full:
        return 'WPA'
    elif 'WEP' in full:
        return 'WEP'
    else:
        return 'Open'

def parse(filename):
    index = 0
    
    document = xml.dom.minidom.parse(filename)
    networks = document.getElementsByTagName("wireless-network")
    
    wifi = []
        
    for network in networks:
        if networks.item(index).getAttribute("type") == "infrastructure":
            gpsinfo = ext_data(networks, "gps-info", index, True)
            plotlat = ext_data(gpsinfo, "avg-lat")
            plotlon = ext_data(gpsinfo, "avg-lon")

            if plotlat==None or plotlon==None:
                index += 1
                continue
            
            essid = escape(ext_data(networks, "essid", index))
            
            encryption = networks.item(index).getElementsByTagName("encryption")
            enc = get_enc(encryption)
                
            bssid = ext_data(networks, 'BSSID', index)
            manuf = ext_data(networks, 'manuf', index)
            channel = ext_data(networks, 'channel', index)
            
            wifi.append((bssid, essid, plotlat, plotlon, enc, manuf, channel))
                        
        index += 1
        
    return wifi
        
def save_db(db, networks):
    conn = sqlite3.connect(db)
    c = conn.cursor()

    for n in networks:
        params_insert = (n[0], n[1], n[2], n[3], n[4], n[5], n[6])
        params_update = (n[1], n[2], n[3], n[4], n[5], n[6], n[0])
        
        bssid = (n[0], )
        c.execute('SELECT * FROM networks WHERE bssid = ?', bssid)
        
        rows = 0
        
        for r in c:
            rows += 1
        
        if rows == 0:
            c.execute("""INSERT INTO networks(bssid, essid, lat, lon, encryption, manufacturer, channel)
                       VALUES(?, ?, ?, ?, ?, ?, ?)""", params_insert)
        else:
            c.execute("""UPDATE networks SET essid = ?, lat = ?, lon = ?, encryption = ?, manufacturer = ?, channel = ? WHERE bssid = ?""", params_update)
        
    conn.commit()
    c.close()

parser = optionparser.OptionParser()
parser.add_option("-i", "--input", dest="filename", help="Path to netxml input file.")
parser.add_option("-o", "--output", dest="database", help="Path to Sqlite database file.")
(options, args) = parser.parse_args()

networks = parse(options.filename)
save_db(options.database, networks)