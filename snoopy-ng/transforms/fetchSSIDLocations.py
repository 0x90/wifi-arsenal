#!/usr/bin/python
# -*- coding: utf-8 -*-
# glenn@sensepost.com_
# snoopy_ng // 2013
# By using this code you agree to abide by the supplied LICENSE.txt

import sys
import os
from MaltegoTransform import *
import logging
from datetime import datetime
from sqlalchemy import create_engine, MetaData, select, and_
from transformCommon import *
from base64 import b64decode
from xml.sax.saxutils import escape
import re
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

limit = 100 # Limit the number of SSID addresses returned.

def main():
    filters.append(wigle.c.ssid == ssid)
    filters.append(wigle.c.overflow == 0)
    s = select([wigle], and_(*filters)).distinct().limit(limit)

    #s = select([ssids.c.ssid]).where(ssids.c.mac==mac).distinct()
    r = db.execute(s)
    results = r.fetchall()
    logging.debug(results)

    TRX = MaltegoTransform()

    illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')


    for address in results:
        if len(results) > 20:
            break
        #ssid = b64decode(ssid)
        #ssid=escape(ssid)
        #ssid = illegal_xml_re.sub('', ssid)
        logging.debug(type(address))

        street_view_url1 = "http://maps.googleapis.com/maps/api/streetview?size=800x800&amp;sensor=false&amp;location=%s,%s" % (str(address['lat']),str(address['long']))
        street_view_url2 = "https://maps.google.com/maps?q=&layer=c&cbp=11,0,0,0,0&cbll=%s,%s " % (str(address['lat']),str(address['long']))
        map_url = "http://maps.google.com/maps?t=h&q=%s,%s"%(str(address['lat']),str(address['long']))
        flag_img = "http://www.geognos.com/api/en/countries/flag/%s.png" % str(address['code']).upper()

        #NewEnt=TRX.addEntity("maltego.Location", address['shortaddress'].encode('utf-8'))
        NewEnt=TRX.addEntity("snoopy.ssidLocation", address['shortaddress'].encode('utf-8'))
        NewEnt.addAdditionalFields("city","city", "strict", address['city'].encode('utf-8'))
        NewEnt.addAdditionalFields("countrycode","countrycode", "strict", address['code'].encode('utf-8'))
        NewEnt.addAdditionalFields("country","country", "strict", address['country'].encode('utf-8'))
        NewEnt.addAdditionalFields("lat","lat", "strict", str(address['lat']))
        NewEnt.addAdditionalFields("long","long", "strict", str(address['long']))
        NewEnt.addAdditionalFields("longaddress","longaddress", "strict", address['longaddress'].encode('utf-8'))
        NewEnt.addAdditionalFields("location.areacode","Area Code", "strict", address['postcode'])
        NewEnt.addAdditionalFields("road","Road", "strict", address['road'].encode('utf-8'))
        NewEnt.addAdditionalFields("streetaddress","streetaddress", "strict", address['shortaddress'].encode('utf-8'))
        NewEnt.addAdditionalFields("ssid","SSID", "strict", address['ssid'])
        NewEnt.addAdditionalFields("state","State", "strict", address['state'].encode('utf-8'))
        NewEnt.addAdditionalFields("area","Area", "strict", address['suburb'].encode('utf-8'))

        NewEnt.addAdditionalFields("googleMap", "Google map", "nostrict", map_url)
        NewEnt.addAdditionalFields("streetView", "Street View", "nostrict", street_view_url2)

        #NewEnt.setIconURL(flag_img)
        logging.debug(street_view_url1)
        NewEnt.setIconURL(street_view_url1)


        NewEnt.addDisplayInformation("<a href='%s'>Click for map </a>" % street_view_url2, "Street view")
        NewEnt.addDisplayInformation("one","two")

    #try:
    TRX.returnOutput()
    #except Exception,e:
    #    print "RARRRR"
    #    print e
    #    print address
    #    exit
main()
#me = MaltegoTransform()
#me.addEntity("maltego.Phrase","hello bob")
#me.returnOutput()                
