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
    global TRX
    ip = TRX.getVar("properties.client_ip")
    if TRX.getVar("client_ip"):
        ip = TRX.getVar("client_ip")

    domain = TRX.getVar("domain")

    filters = []

    if ip:
        filters.append( sslstrip.c.client == ip )
        if domain:
            filters.append( sslstrip.c.domain == domain)
        
        s = select([sslstrip.c.key, sslstrip.c.value], and_(*filters)).distinct()
        results = db.execute(s).fetchall()

        for res in results:
            key, value = res
            NewEnt=TRX.addEntity("snoopy.sslstripResult", key)
            NewEnt.addAdditionalFields("key","key", "strict", value)      
            NewEnt.addAdditionalFields("value","Value", "strict", value)      

        TRX.returnOutput()

    #Custom query per transform, but apply filter with and_(*filters) from transformCommon.
    filters = []
    
    filters.extend( (leases.c.mac == mac, sslstrip.c.client == leases.c.ip))

    if domain:
        filters.append( sslstrip.c.domain == domain )
    s = select([sslstrip.c.domain, leases.c.mac, leases.c.ip], and_(*filters))
    r = db.execute(s)
    results = r.fetchall()
    TRX = MaltegoTransform()
    illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')

    for res in results:
        domain, client_mac, client_ip = res
        NewEnt=TRX.addEntity("snoopy.Site", domain)
        NewEnt.addAdditionalFields("domain","domain", "strict",domain)
        NewEnt.addAdditionalFields("mac","Client Mac", "strict",client_mac)
        NewEnt.addAdditionalFields("client_ip","Client IP", "strict",client_ip)

    TRX.returnOutput()

main()
#me = MaltegoTransform()
#me.addEntity("maltego.Phrase","hello bob")
#me.returnOutput()                
