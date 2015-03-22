#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
from sqlalchemy import MetaData, Table, Column, String, Integer
from scapy.all import ARP, Ether

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class Snarf():
    """Grabs BSSID from arp frames (thanks Hubert)"""
    def __init__(self,**kwargs):
        self.device_bssids = {}

    @staticmethod
    def get_tables():
        """Make sure to define your table here"""
        table = Table('bssid_arps', MetaData(),
                      Column('mac', String(12), primary_key=True),
                      Column('bssid', String(12), primary_key=True),
                      Column('sunc', Integer, default=0))
        return [table]

    def proc_packet(self, packet):
        if packet.haslayer(ARP) and packet.haslayer(Ether):
            mac = re.sub(':', '', packet.addr2)
            bssid = packet[Ether].dst
            if bssid != 'ff:ff:ff:ff:ff:ff':
                self.device_bssids[(mac, bssid)] = 0

    def get_data(self):
        tmp = []
        sunc = []
        for k, v in self.device_bssids.iteritems():
            if v == 0:
                tmp.append( {"mac": k[0], "bssid": k[1]} )
                sunc.append((k[0], k[1]))
        if sunc:
            for foo in sunc:
                mac, bssid = foo[:2]
                self.device_bssids[(mac, bssid)] = 1
            return ("bssid_arps", tmp)
        return []
