#!/usr/bin/python
# -*- coding: utf-8 -*-
# dominic@sensepost.com
# snoopy_ng // 2014
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
    filters.append(weblogs.c.client_ip==ip)
    s = select([weblogs.c.host, weblogs.c.path, weblogs.c.cookies], and_(*filters))
    logging.debug(s) 
    #s = select([ssids.c.ssid]).where(ssids.c.mac==mac).distinct()
    r = db.execute(s)
    results = r.fetchall()
    logging.debug(results)
    #results = [t[0] for t in results]
    TRX = MaltegoTransform()

    illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')


    for res in results:
        #logging.debug(res)
        host, path, cookies = res
        logging.debug(host)
        #logging.debug(path)
        logging.debug(cookies)
        if len(cookies) > 2:
            foo = cookies.split(", ")
            for cookie in foo:
                name, value = cookie.split(": ")
                name = name.split('"')[1]
                value = value.split('"')[1]
                logging.debug(name)
                logging.debug(value)
                NewEnt=TRX.addEntity("snoopy.Cookie", name)
                NewEnt.addAdditionalFields("value","Value", "strict",value)
                NewEnt.addAdditionalFields("fqdn","Domain", "strict",host)
                #NewEnt.addAdditionalFields("path","Path", "strict",path)
                NewEnt.addAdditionalFields("ip","Client IP", "strict",ip)

    TRX.returnOutput()

main()
#me = MaltegoTransform()
#me.addEntity("maltego.Phrase","hello bob")
#me.returnOutput()                
