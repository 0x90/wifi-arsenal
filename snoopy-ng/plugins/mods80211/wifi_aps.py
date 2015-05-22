#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
from sqlalchemy import MetaData, Table, Column, Integer, String, Unicode, DateTime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot11Beacon, Dot11Elt
from base64 import b64encode
from includes.common import snoop_hash, printFreq 
import os
from includes.fonts import *
from includes.prox import prox
from includes.fifoDict import fifoDict
import datetime
from includes.mac_vendor import mac_vendor

#N.B If you change b64mode to False, you should probably change
# the ssid colum to type Unicode.
b64mode = False

class Snarf():
    """Extract BSSIDs (i.e. Access Points)"""

    def __init__(self, **kwargs):

        self.hash_macs = kwargs.get('hash_macs', False)
        proxWindow = kwargs.get('proxWindow', 300)
        self.verb = kwargs.get('verbose', 0)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]

        self.prox = prox(proxWindow=proxWindow, identName="mac", pulseName="num_beacons")
        self.ap_names = fifoDict()
        self.device_vendor = fifoDict()

        self.mv = mac_vendor()
        self.lastPrintUpdate = 0

    @staticmethod
    def get_tables():
        """Make sure to define your table here"""
        table = Table('wifi_AP_obs', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('first_obs', DateTime, primary_key=True, autoincrement=False),
                      Column('last_obs', DateTime),
                      Column('num_beacons', Integer),
                      Column('sunc', Integer, default=0))

        table2 = Table('wifi_AP_ssids', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('ssid', String(100), primary_key=True, autoincrement=False),
                      Column('sunc', Integer, default=0))

        return [table, table2]

    def proc_packet(self, p):
        if p.haslayer(Dot11Beacon) and p[Dot11Elt].info != '' and re.match("[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]", p.addr2):
            mac = re.sub(':', '', p.addr2)
            timeStamp = datetime.datetime.fromtimestamp(int(p.time))
            vendor = self.mv.lookup(mac[:6])
            if self.hash_macs == "True":
                mac = snoop_hash(mac)
            if b64mode:
                ssid = b64encode(p[Dot11Elt].info)
            else:
                ssid = p[Dot11Elt].info.decode('utf-8', 'ignore')
            try:
                sig_str = -(256-ord(p.notdecoded[-4:-3])) #TODO: Use signal strength
            except:
                logging.error("Unable to extract signal strength")
                logging.error(p.summary())

            self.prox.pulse(mac,timeStamp)
            self.ap_names.add((mac,ssid))
            self.device_vendor.add((mac,vendor))

    def get_data(self):
        proxSess = self.prox.getProxs()
        ap_names_rtn = []
        for mac_ssid in self.ap_names.getNew():
            mac,ssid = mac_ssid
            ap_names_rtn.append({"mac": mac, "ssid": ssid})

        vendors = []
        for mac_vendor in self.device_vendor.getNew():
            mac, vendor = mac_vendor
            vendorShort = vendor[0]
            vendorLong = vendor[1]
            vendors.append({"mac": mac, "vendor": vendorShort, "vendorLong": vendorLong})
                
        if proxSess and self.verb > 0 and abs(os.times()[4] - self.lastPrintUpdate) > printFreq:
            logging.info("Sub-plugin %s%s%s currently observing %s%d%s Access Points" % (GR,self.fname,G,GR,self.prox.getNumProxs(),G))
            self.lastPrintUpdate = os.times()[4]


        data = [("wifi_AP_obs", proxSess), ("wifi_AP_ssids", ap_names_rtn), ("vendors",vendors)]
        return data
