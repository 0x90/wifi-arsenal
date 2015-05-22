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
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

def main():
#    print "Content-type: xml\n\n";
#    MaltegoXML_in = sys.stdin.read()
#    logging.debug(MaltegoXML_in)
#    if MaltegoXML_in <> '':
#     m = MaltegoMsg(MaltegoXML_in)


    # Get GPS positions during this session
    ft = [ (gps.c.run_id == sess.c.run_id), (gps.c.systemTime >= sess.c.start), (gps.c.systemTime <= sess.c.end ) ]
    sg = select([gps.c.lat, gps.c.lon], and_(*ft))
    gps_c = db.execute(sg).fetchall()

    if gps_c:
        firstGPS,lastGPS = (gps_c[0][0], gps_c[0][1]), (gps_c[-1][0], gps_c[-1][1])
        latVariance = abs(sorted(gps_c)[0][0]-sorted(gps_c)[-1][0])
        lonVariance = abs(sorted(gps_c)[0][1]-sorted(gps_c)[-1][1])

    s = select([sess.c.location], and_(*filters)).distinct()
    r = db.execute(s)
    results = r.fetchall()
  
    for location in results:
        location = location[0]
        logging.debug(location)
        NewEnt=TRX.addEntity("snoopy.DroneLocation", location)
        #NewEnt.addAdditionalFields("location","location", "strict", location)
        NewEnt.addAdditionalFields("drone","drone", "strict", drone)
        NewEnt.addAdditionalFields("start_time", "start_time", "strict", start_time)
        NewEnt.addAdditionalFields("end_time", "end_time", "strict", end_time)
        if gps_c:
            NewEnt.addAdditionalFields("start_gps", "start_gps", "strict", str(firstGPS))
            NewEnt.addAdditionalFields("end_gps", "end_gps", "strict", str(lastGPS))
            NewEnt.addAdditionalFields("var_gps", "var_gps", "strict", str(latVariance+lonVariance))

    TRX.returnOutput()

main()
