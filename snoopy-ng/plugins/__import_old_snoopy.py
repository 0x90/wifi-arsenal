#!/usr/bin/env python
# -*- coding: utf-8 -*-
# TODO: Change this since updating database format

import sys
import logging
from sqlalchemy import Float, DateTime, String, Integer, Table, MetaData, Column #As required
from threading import Thread
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(filename)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
import time
from collections import deque
from random import randint
import datetime
from threading import Thread
import collections
import csv
import re
import os
from includes.fonts import *

class Snoop(Thread):
    """Import from old Snoopy format. Only handles probe_data.txt file for now."""
    def __init__(self, **kwargs):
        Thread.__init__(self)
        self.RUN = True

        self.DELTA_PROX = 300
        self.proximity_sessions = {}
        self.device_ssids = {}

        # Process arguments passed to module
        self.probes = kwargs.get('probes_file',"probe_data.txt")
        self.done_reading = False
        self.done_line = False

        self.verb = kwargs.get('verbose', 0)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]

    def run(self):

        logging.info("Plugin %s%s%s processing '%s%s%s' file for data. This may take some time..." % (GR,self.fname,G,GR,self.probes,G))
        with open(self.probes) as f:
            for line in f:
                self.done_line = False
                try:
                    self.proc_line(line)
                except Exception, e:
                    logging.error("Encountered bad line, ignoring. Error was \"%s\". Bad line was:\n\t%s" %(e,line))
                    pass
        self.done_reading = True

    def proc_line(self,line):
        # Following 10 lines borrowed from old Snoopy
        line=line.rstrip()
        # e.g "N900-glenn","1344619634_27185","lough001","00:c0:1b:0b:54:89","tubes","-87","Aug 10, 2012 18:29:58.779969000"
        c=csv.reader([line],delimiter=",")
        r=next(iter(c), None)
        r[6]=re.sub('\..*','',r[6])
        r[3]=re.sub(':','',r[3]) #Remove colons from mac
        try:
            r[6]=time.mktime(time.strptime(r[6],"%b %d, %Y %H:%M:%S"))  #Until we can update N900's tshark to use frame.time_epoch
        except Exception,e:
            pass
        
        drone, location, mac, ssid, timestamp = r[0], r[2], r[3], r[4], r[6]
        if len(r) != 7:
            #logging.error("Encountered bad line, ignoring:\n\t%s" % line)
            return
        timestamp = datetime.datetime.fromtimestamp(timestamp)
        #1. First, do proximity_sessions        
        #Key is (drone,location,mac), revealing a list of proximity sessions
        if (drone,location,mac) not in self.proximity_sessions:        
            nps = (timestamp, timestamp, 1)
            self.proximity_sessions[(drone,location,mac)] = [nps]
        else:
            #Get last prox session in list
            cps = self.proximity_sessions[(drone,location,mac)][-1]
            first_obs, last_obs, num_probes = cps
            time_diff = timestamp - last_obs
            if time_diff >= datetime.timedelta(seconds=self.DELTA_PROX):
                #Expired. Create a  new one.
                self.proximity_sessions[(drone,location,mac)].append((timestamp, timestamp, 1))
            else:
                #Just update the old one
                self.proximity_sessions[(drone,location,mac)][-1] = (first_obs, timestamp, num_probes+1)

        #2. Second, do SSIDs
        self.device_ssids[(mac, ssid)] = 0

        self.done_line = True

    def get_data(self):
        if self.done_reading and self.done_line:
            #1. Prepare prox sessions
            proxs = []
            for k,v in self.proximity_sessions.iteritems():
                drone, location, mac = k
                for session in v:
                    first_obs, last_obs, num_probes = session
                    proxs.append({'drone':drone, 'location':location, 'mac':mac, 'first_obs':first_obs, 'last_obs':last_obs, 'num_probes':num_probes})

            self.proximity_sessions = {}
            self.done_reading = False #To make it not keep giving the same data over and over
            logging.info("Done processing '%s%s%s' for data. I won't read it again. This plugin is done." % (GR,self.probes,G))

            #2. Prepare ssids
            ssids = []
            for k,v in self.device_ssids.iteritems():
                mac,ssid = k
                ssids.append( {"mac": mac, "ssid": ssid} )            

            return [('proximity_sessions', proxs), ('ssids', ssids)]
            
        else:
            return []

    def is_ready(self):
        return True

    def stop(self):
        self.RUN = False

    @staticmethod
    def get_parameter_list():
        info = {"info" : "Import data from old Snoopy.",
                "parameter_list" : [ ("probes_file=<probe_data.txt>","Path to probe_data.txt file."),
                                   ]
                }
        return info

    @staticmethod
    def get_tables():
        """Make sure to define your table here"""
        table = Table('proximity_sessions', MetaData(),
                      Column('mac', String(64), primary_key=True), #Len 64 for sha256
                      Column('first_obs', DateTime, primary_key=True, autoincrement=False),
                      Column('last_obs', DateTime),
                      Column('num_probes', Integer),
                      Column('sunc', Integer, default=0),
                      #Column('location', String(length=60)),
                      #Column('drone', String(length=20), primary_key=True))

        return [table]

if __name__ == "__main__":
    Snoop().start()
