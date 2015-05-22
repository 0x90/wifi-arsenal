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
from sqlalchemy import create_engine, MetaData, select, and_, func
from transformCommon import *
from base64 import b64decode
from xml.sax.saxutils import escape
import re
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

def main():

##    filters.append(wigle.c.ssid == ssid)
##    filters.append(wigle.c.overflow == 0)
##    s = select([wigle], and_(*filters)).distinct().limit(limit)
    #s = select([ssids.c.ssid]).where(ssids.c.mac==mac).distinct()
##    r = db.execute(s)
##    results = r.fetchall()
##    logging.debug(results)
##    TRX = MaltegoTransform()
    illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')


    #location = "ITWeb_2013"
    filters = []
    filters.append(sess.c.location == location)
    filters.append(sess.c.run_id == ssids.c.run_id)
    filters.append(ssids.c.ssid == wigle.c.ssid)
    sub_q = select([wigle.c.country, func.count(wigle.c.country)], and_(*filters)).group_by(wigle.c.ssid).having(func.count()==1)
    s = select([sub_q.c.country,func.count(sub_q.c.country)], and_(sub_q.c.country != "")).group_by(sub_q.c.country)

    r = db.execute(s)
    results = r.fetchall() 

    for res in results:
        country, count = res
        if count > 2:
            country = illegal_xml_re.sub('', country)
            NewEnt=TRX.addEntity("maltego.Location", country)
            NewEnt.addAdditionalFields("count", "count", "strict", str(count))
            NewEnt.setWeight(count)

    TRX.returnOutput()

main()
