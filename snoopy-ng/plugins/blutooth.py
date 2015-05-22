#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import logging
from sqlalchemy import MetaData, Table, Column, String, Unicode, Integer, DateTime
from threading import Thread
import os
from includes.fonts import *
from includes.prox import prox
from includes.fifoDict import fifoDict
from includes.common import snoop_hash, printFreq
import datetime
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(filename)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

class Snoop(Thread):
    def __init__(self, **kwargs):
        Thread.__init__(self)
        self.RUN = True
        self.verb = kwargs.get('verbose', 0)
        self.proxWindow = kwargs.get('proxWindow', 300)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]

        self.prox = prox(proxWindow=self.proxWindow, identName="mac", verb=0, callerName=self.fname)
        self.vendors = fifoDict(names=("mac", "vendor", "vendorLong"))
        self.btDetails = fifoDict(names=("mac", "name", "classType", "manufac", "lmpVer"))
        self.lastPrintUpdate = 0

    def run(self):
        from includes.bluScan import scan
        reported = False
        while self.RUN:
            logging.debug("Scanning for bluetooth devices")
            scanResults = scan()
            if scanResults:
                for result in scanResults:
                    mac = result['mac']
                    name = result['name'].decode('utf-8')
                    vendor,vendorLong = result['vendor'], result['vendorLong']
                    classType = result['classType']
                    manufac = result['manufac']
                    lmpVer = result['lmpVer']
    
                    self.prox.pulse(mac)
                    self.vendors.add((mac, vendor, vendorLong))
                    self.btDetails.add((mac,name,classType,manufac,lmpVer))

                    if self.verb > 1:
                        logging.info("Plugin %s%s%s watching device '%s%s%s' (%s%s%s) with name '%s%s%s'." % (GR,self.fname,G,GR,mac,G,GR,vendorLong,G,GR,name,G))

            tmptimer=0
            while self.RUN and tmptimer < 5:
                time.sleep(0.1)
                tmptimer += 0.1

    def stop(self):
        logging.info("Shutting down Bluetooth scanner, may take 30 seconds...")
        self.RUN = False

    def is_ready(self):
        return True

    @staticmethod
    def get_parameter_list():
        info = {"info" : "Discovers Bluetooth devices.",
                "parameter_list" : None
                }
        return info

    def get_data(self):
        """Ensure data is returned in the form of a SQL row."""
        proxSess =  self.prox.getProxs()
        btList = self.btDetails.getNew()
        vendorsList = self.vendors.getNew()

        if proxSess and self.verb > 0 and abs(os.times()[4] - self.lastPrintUpdate) > printFreq:
            logging.info("Sub-plugin %s%s%s currently observing %s%d%s client devices" % (GR,self.fname,G,GR,self.prox.getNumProxs(),G))
            self.lastPrintUpdate = os.times()[4]
            
        return [("bluetooth_obs", proxSess), ("vendors", vendorsList), ("bluetooth_details", btList)]
    

    @staticmethod
    def get_tables():

        table = Table('bluetooth_obs', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('first_obs', DateTime, primary_key=True, autoincrement=False),
                      Column('last_obs', DateTime),
                      Column('sunc', Integer, default=0),
                    )

        table2 = Table('bluetooth_details', MetaData(),
                    Column('mac', String(64), primary_key=True), #Len 64 for sha256
                    Column('name', String(64)),
                    Column('classType', String(24)),
                    Column('manufac', String(64)),
                    Column('lmpVer', String(12)))

        table3 = Table('vendors', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('vendor', String(20) ),
                      Column('vendorLong', String(50) ),
                      Column('sunc', Integer, default=0))


        return [table, table2, table3]


if __name__=="__main__":
    Snoop().start()
