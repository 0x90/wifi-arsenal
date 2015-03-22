#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
from sqlalchemy import MetaData, Table, Column, Integer, String, Unicode
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#from scapy.all import Dot11Beacon, Dot11Elt
from collections import deque
from includes.fonts import *
import os
import cpyrit.pckttools
from base64 import b64encode

class Snarf():
    """Capture WPA handshakes"""

    def __init__(self, **kwargs):
        self.handshakes = deque()
        self.verb = kwargs.get('verbose', 0)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]
        self.cp = cpyrit.pckttools.PacketParser(new_ap_callback=None, new_auth_callback=self.auth_handler)

    def auth_handler(self, auth):
        if auth.station.ap.isCompleted():
            json_eap = {"sta_mac": auth.station.mac, "ap_mac" : auth.station.ap.mac, "ssid": auth.station.ap.essid, "anonce": b64encode(auth.anonce), "snonce": b64encode(auth.snonce), "keymic": b64encode(auth.keymic), "keymic_frame": b64encode(auth.keymic_frame), "version": auth.version, "quality": auth.quality, "spread": auth.spread}
            self.handshakes.append(json_eap)
            if self.verb > 0:
                logging.info("Sub-plugin %s%s%s captured new handshake for %s%s%s" % (GR,self.fname,G,GR,auth.station.ap.essid, G))

    @staticmethod
    def get_tables():
        """Make sure to define your table here"""
        table = Table('wpa_handshakes', MetaData(),
                      Column('ssid', String(64), primary_key=True),
                      Column('ap_mac', String(12), primary_key=True, autoincrement=False),
                      Column('sta_mac', String(12), primary_key=True, autoincrement=False),
                      Column('anonce', String(50), primary_key=True, autoincrement=False),
                      Column('snonce', String(50)),
                      Column('keymic', String(24)),
                      Column('keymic_frame', String(180)),
                      Column('version', String(10)),
                      Column('quality', Integer),
                      Column('spread', Integer),
                      Column('sunc', Integer, default=0))
        return [table]

    def proc_packet(self, p):
        self.cp.parse_packet(p)


    def get_data(self):
        rtnData=[]
        while self.handshakes:
            rtnData.append(self.handshakes.popleft())
        if rtnData:
            return [("wpa_handshakes", rtnData)]
