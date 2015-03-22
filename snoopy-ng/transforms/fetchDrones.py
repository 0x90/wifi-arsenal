#!/usr/bin/python
# -*- coding: utf-8 -*-
# glenn@sensepost.com 
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
#    s = select([proxs.c.drone], and_(*filters)).distinct()
    s = select([sess.c.drone], and_(*filters)).distinct()
    logging.debug(filters)
    logging.debug(s)
    r = db.execute(s)
    results = r.fetchall()
    results = [t[0] for t in results]
    TRX = MaltegoTransform()

    for drone in results:
        logging.debug(drone)
        NewEnt=TRX.addEntity("snoopy.Drone", drone)
        NewEnt.addAdditionalFields("properties.drone","drone", "strict",drone)
        NewEnt.addAdditionalFields("start_time", "start_time", "strict", start_time)
        NewEnt.addAdditionalFields("end_time", "end_time", "strict", end_time)
        #NewEnt.addAdditionalFields("drone", "drone", "strict", drone)
        #NewEnt.addAdditionalFields("location", "location", "strict", location)
    TRX.returnOutput()

main()
