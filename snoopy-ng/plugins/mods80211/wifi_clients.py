#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import logging
import re
from sqlalchemy import MetaData, Table, Column, String, Integer, DateTime
from includes.common import snoop_hash, printFreq
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot11ProbeReq, Dot11Elt
import datetime
from includes.fonts import *
import os
from includes.prox import prox
from includes.mac_vendor import mac_vendor
from includes.fifoDict import fifoDict

class Snarf():
    """Observe WiFi client devices based on probe-requests emitted."""

    def __init__(self, **kwargs):

        self.proxWindow = kwargs.get('proxWindow', 300)
        self.hash_macs = kwargs.get('hash_macs', False)
        self.verb = kwargs.get('verbose', 0)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]
        self.prox = prox(proxWindow=self.proxWindow, identName="mac", pulseName="num_probes", verb=0, callerName=self.fname)
        self.device_vendor = fifoDict(names=("mac", "vendor", "vendorLong"))
        self.client_ssids = fifoDict(names=("mac","ssid"))

        self.mv = mac_vendor()    
        self.lastPrintUpdate = 0

    @staticmethod
    def get_tables():
        """Make sure to define your table here"""
        table = Table('wifi_client_obs', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('first_obs', DateTime, primary_key=True, autoincrement=False),
                      Column('last_obs', DateTime),
                      Column('num_probes', Integer),
                      Column('sunc', Integer, default=0),
                    )

        table2 = Table('vendors', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('vendor', String(20) ),
                      Column('vendorLong', String(50) ),
                      Column('sunc', Integer, default=0))

        table3 = Table('wifi_client_ssids', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('ssid', String(100), primary_key=True, autoincrement=False),
                      Column('sunc', Integer, default=0))

        return [table, table2, table3]

    def proc_packet(self,p):
        
        if not p.haslayer(Dot11ProbeReq):
            return
        timeStamp = datetime.datetime.fromtimestamp(int(p.time))
        mac = re.sub(':', '', p.addr2)
        vendor = self.mv.lookup(mac[:6])

        if self.hash_macs == "True":
            mac = snoop_hash(mac)

        try:
            sig_str = -(256-ord(p.notdecoded[-4:-3])) #TODO: Use signal strength
        except:
            #logging.error("Unable to extract signal strength")
            pass 
        self.prox.pulse(mac, timeStamp) #Using packet time instead of system time allows us to read pcaps
        self.device_vendor.add((mac,vendor[0],vendor[1]))

        if p[Dot11Elt].info != '':
            ssid = p[Dot11Elt].info.decode('utf-8')
            ssid = re.sub("\n", "", ssid)
            if self.verb > 1 and len(ssid) > 0:
                logging.info("Sub-plugin %s%s%s noted device %s%s%s (%s%s%s) probing for %s%s%s" % (GR,self.fname,G,GR,mac,G,GR,vendor[0],G,GR,ssid,G))
            if len(ssid) > 0:
                self.client_ssids.add((mac,ssid))

    def get_data(self):
        """Ensure data is returned in the form (tableName,[colname:data,colname:data]) """
        proxSess =  self.prox.getProxs()
        vendors = self.device_vendor.getNew()
        ssid_list = self.client_ssids.getNew()

        if proxSess and self.verb > 0 and abs(os.times()[4] - self.lastPrintUpdate) > printFreq:
            logging.info("Sub-plugin %s%s%s currently observing %s%d%s client devices" % (GR,self.fname,G,GR,self.prox.getNumProxs(),G))
            self.lastPrintUpdate = os.times()[4]

        data = [("wifi_client_obs",proxSess), ("vendors",vendors), ("wifi_client_ssids", ssid_list)]
        return data

