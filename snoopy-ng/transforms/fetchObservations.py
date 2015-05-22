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

    #Custom query per transform, but apply filter with and_(*filters) from transformCommon.
    #s = select([proxs.c.location, proxs.c.drone, proxs.c.first_obs, proxs.c.last_obs], and_(*filters))

    #ft = [ (gps.c.run_id == sess.c.run_id), (gps.c.systemTime >= sess.c.start), (gps.c.systemTime <= sess.c.end ) ]

    s = select([sess.c.location, sess.c.drone, proxs.c.first_obs, proxs.c.last_obs], and_(*filters))
    r = db.execute(s)
    results = r.fetchall()

    for r in results:
        location = r[0]
        drone = r[1]
        start_time = r[2].strftime("%Y-%m-%d %H:%M:%S.%f")
        end_time = r[3].strftime("%Y-%m-%d %H:%M:%S.%f")

        # Get GPS positions during the observation period of this session
        ft = [ (gps.c.run_id == sess.c.run_id), (gps.c.systemTime >= start_time), (gps.c.systemTime <= end_time ) ]
        sg = select([gps.c.lat, gps.c.lon], and_(*ft))
        gps_c = db.execute(sg).fetchall()

        if gps_c:
            firstGPS,lastGPS = (gps_c[0][0], gps_c[0][1]), (gps_c[-1][0], gps_c[-1][1])
            latVariance = abs(sorted(gps_c)[0][0]-sorted(gps_c)[-1][0])
            lonVariance = abs(sorted(gps_c)[0][1]-sorted(gps_c)[-1][1])
            logging.debug(firstGPS)
            logging.debug(type(firstGPS))


        td = (r[3] - r[2]).seconds
        if td == 0:
            td = 1
        hours, remainder = divmod(td, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration = ""
        if hours > 0:
            duration += "%s hour" % hours
            if hours > 1:
                duration +='s'
        if minutes > 0:
            if duration != "":
                duration += ", "
            duration += "%s min" % minutes
            if minutes > 1:
                duration +='s'
        if seconds > 0:
            if duration != "":
                duration += ", "
            duration += "%s sec" % seconds
            if seconds > 1:
                duration +='s'
        observation = "Drone: %s\nLocation: %s\n(%s)" % (drone,location,duration)

        NewEnt=TRX.addEntity("snoopy.Observation", observation )
        #NewEnt=TRX.addEntity("snoopy.DroneLocation", location)
        NewEnt.addAdditionalFields("location","location", "strict", location)
        NewEnt.addAdditionalFields("drone","drone", "strict", drone)
        NewEnt.addAdditionalFields("start_time", "start_time", "strict", start_time)
        NewEnt.addAdditionalFields("end_time", "end_time", "strict", end_time)
        if gps_c:
            NewEnt.addAdditionalFields("start_gps", "start_gps", "strict", str(firstGPS))
            NewEnt.addAdditionalFields("end_gps", "end_gps", "strict", str(lastGPS))
            NewEnt.addAdditionalFields("var_gps", "var_gps", "strict", str(latVariance+lonVariance))


    TRX.returnOutput()

main()
