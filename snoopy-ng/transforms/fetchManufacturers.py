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

    illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')

    filters = []
    filters.append(sess.c.location == location)
    filters.append(sess.c.run_id == vends.c.run_id)
    #filters.append(ssids.c.ssid == wigle.c.ssid)
    s = select([vends.c.vendor,vends.c.vendorLong, func.count(vends.c.vendor)], and_(*filters)).group_by(vends.c.vendor)

    r = db.execute(s)
    results = r.fetchall() 

    for res in results:
        vendor, vendorLong, count = res
        if count > 2:
            vendor = illegal_xml_re.sub('', vendor)
            NewEnt=TRX.addEntity("snoopy.Client", vendor)
            NewEnt.addAdditionalFields("vendor", "vendor", "strict", vendor)
            NewEnt.addAdditionalFields("vendorLong", "vendorLong", "strict", vendorLong)
            NewEnt.addAdditionalFields("count", "count", "strict", str(count))
            NewEnt.setWeight(count)

    TRX.returnOutput()

main()
