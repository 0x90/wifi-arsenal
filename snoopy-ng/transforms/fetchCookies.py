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

def main():
#    print "Content-type: xml\n\n";
#    MaltegoXML_in = sys.stdin.read()
#    logging.debug(MaltegoXML_in)
#    if MaltegoXML_in <> '':
#     m = MaltegoMsg(MaltegoXML_in)

    #Custom query per transform, but apply filter with and_(*filters) from transformCommon.
    filters = []
    #filters.extend((cookies.c.client_mac==mac, cookies.c.baseDomain==domain)) #Bug: baseDomain being returned as full URL.
    filters.extend((cookies.c.client_mac==mac, cookies.c.host==domain))
    s = select([cookies.c.name, cookies.c.value], and_(*filters))
    logging.debug(s) 
    #s = select([ssids.c.ssid]).where(ssids.c.mac==mac).distinct()
    r = db.execute(s)
    results = r.fetchall()
    logging.debug(results)
    #results = [t[0] for t in results]
    TRX = MaltegoTransform()

    illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')


    for cookie in results:
        logging.debug(cookie)
        name, value = cookie
        NewEnt=TRX.addEntity("snoopy.Cookie", name)
        NewEnt.addAdditionalFields("value","Value", "strict",value)
        NewEnt.addAdditionalFields("fqdn","Domain", "strict",domain)
        NewEnt.addAdditionalFields("mac","Client Mac", "strict",mac)

    TRX.returnOutput()

main()
#me = MaltegoTransform()
#me.addEntity("maltego.Phrase","hello bob")
#me.returnOutput()                
