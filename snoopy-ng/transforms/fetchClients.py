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
    #db.echo=True

    #Need to implement outer join at some point:
    # s=select([proxs.c.mac]).outerjoin(vends, proxs.c.mac == vends.c.mac) #Outer join

    sl = select([leases.c.mac, leases.c.hostname]).distinct()
    lease_list = dict ( db.execute(sl).fetchall() )
 
    #filters.append(proxs.c.mac == vends.c.mac) # Replaced with JOIN
    j = proxs.outerjoin(vends, proxs.c.mac == vends.c.mac)
    s = select([proxs.c.mac,vends.c.vendor, vends.c.vendorLong], and_(*filters)).select_from(j).distinct()
    logging.debug(s)
    #s = select([proxs.c.mac,vends.c.vendor, vends.c.vendorLong], and_(*filters))
    if ssid:
        nfilters=[]
        nfilters.append(ssids.c.ssid == ssid)
        nfilters.append(ssids.c.mac == vends.c.mac)
        s = select([ssids.c.mac,vends.c.vendor, vends.c.vendorLong], and_(*nfilters))

    #logging.debug(s)
    #s = select([proxs.c.mac,vends.c.vendor, vends.c.vendorLong], and_(proxs.c.mac == vends.c.mac, proxs.c.num_probes>1 ) ).distinct()

    cwdF = [cookies.c.run_id == sess.c.run_id]
    cw = select([cookies.c.client_mac], and_(*cwdF))
    logging.debug(cw)

    r = db.execute(s)
    results = r.fetchall()
    TRX = MaltegoTransform()
    for mac,vendor,vendorLong in results:
        hostname = lease_list.get(mac)

        if hostname:
            NewEnt=TRX.addEntity("snoopy.Client", "%s\n(%s)" %(vendor,hostname))
        else:
            NewEnt=TRX.addEntity("snoopy.Client", "%s\n(%s)" %(vendor,mac[6:]))
        NewEnt.addAdditionalFields("mac","mac address", "strict",mac)
        NewEnt.addAdditionalFields("vendor","vendor", "nostrict", vendor)
        #NewEnt.addAdditionalFields("vendorLong","vendorLong", "nostrict", vendorLong)
        #    ^ Going via a TDS crashes for resutls >1000. Weird? 

    TRX.returnOutput()

main()
