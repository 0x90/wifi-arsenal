#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from sqlalchemy import Float, Numeric, DateTime, String, Integer, Table, MetaData, Column #As required
from threading import Thread
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(filename)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
import time
from collections import deque
from random import randint
import datetime
from threading import Thread
from gps import *#gps, WATCH_ENABLE
from math import isnan
import os
from includes.fonts import *
from dateutil import parser

class Snoop(Thread):
    """Gets GPS co-ordinates of drone using gpsd."""
    def __init__(self, **kwargs):
        Thread.__init__(self)
        self.RUN = True
        self.data_store = deque(maxlen=1000)
        self.ready = True
        # Process arguments passed to module
        self.freq = int(kwargs.get('freq', 30))
        self.verb = kwargs.get('verbose', 0)
        self.lat = kwargs.get('lat')
        self.long = kwargs.get('long')
        self.port = kwargs.get('port', 2947)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]

        self.last_lat = 0
        self.last_long = 0
        self.last_alt = 0

        if self.lat or self.long:
            try:
                self.lat = float(self.lat)
                self.long = float(self.long)
                logging.info("Plugin %s%s%s using manual GPS co-ordinates: %s(%0.4f,%0.4f)%s. Will plot every %s%d%s seconds." % (GR,self.fname,G,GR,self.lat,self.long,G,GR,self.freq,G))
            except Exception, e:
                logging.error("Lat and long parameters should both be present, and be numeric.")
                exit(-1)
        else:
            try:
                self.gpsd = gps(mode=WATCH_ENABLE, port=self.port)
            except Exception, e:
                logging.error("Unable to query gpsd daemon: '%s'" % e)
                exit(-1)

    def run(self):
        lastMessage = 0
        gotGoodFixOnce = False
        while self.RUN:
            now = datetime.datetime.now()
            n=float('NaN')
            res = {'alt':n, 'eps':n, 'ept':n, 'epv':n, 'epx':n, 'epy':n, 'lat':n, 'lon':n, 'time':"1970", 'systemTime':now}
            if self.lat and self.long:
                res['lat'] = self.lat
                res['lon'] = self.long
                res['time'] = parser.parse(res['time']).now()
                gotGoodFixOnce = True
                self.data_store.append(res)
                if self.verb > 1:
                     logging.info("Plugin %s%s%s using manual GPS co-ordinates: %s(%0.4f,%0.4f)%s." % (GR,self.fname,G,GR,self.lat,self.long,G))
            else:
                resN = dict(self.gpsd.next())
                if resN and 'lat' in resN and 'lon' in resN:
                    for k in resN:
                        if k in res:
                            res[k] = resN[k]
                    if res['time'] != n:
                        try:
                            res['time'] = parser.parse(res['time']).now()
                        except Exception,e:
                            logging.error(e)
                    self.data_store.append(res)
                    gotGoodFixOnce = True
                    lastMessage = os.times()[4]
                    if self.verb > 0:
                        slat = float("%0.4f" %(res.get('lat')))
                        slong = float("%0.4f" %(res.get('lon')))
                        salt=-1
                        if res.get('alt') != n:
                            salt = int(res.get('alt'))
                        if slat != self.last_lat or slong != self.last_long or abs(salt - self.last_alt) > 2 and self.verb > 0:
                            logging.info("Plugin %s%s%s indicated new GPS position: %s(%s,%s) @ %sm%s" % (GR,self.fname,G,GR,slat,slong,salt,G))
                            self.last_lat, self.last_long, self.last_alt = slat, slong, salt
                else:
                    dt = os.times()[4]
                    if abs( dt - lastMessage) > 30:
                        logging.debug("No good signal on GPS yet... (%s)"%(str(res)))
                        if self.verb > 0:
                            logging.warning("Plugin %s%s%s looking for good GPS fix..." % (GR,self.fname,G) )
                        lastMessage = dt

            if self.freq == 0 and gotGoodFixOnce:
                self.RUN = False

            i = 0
            while self.RUN and i < self.freq+1:
                time.sleep(1)
                i+=1

    def is_ready(self):
        return self.ready

    def stop(self):
        self.RUN = False

    @staticmethod
    def get_parameter_list():
        info = {"info" : "Queries gpsd server for GPS co-ordinates. Ensure the gpsd daemon is running, and on port 2947.",
                "parameter_list" : [ ("freq=<seconds>","Frequency to poll GPS. Set to 0 to get one fix, and end."),
                                     ("lat=<LAT>","Manually set GPS latitude"),
                                     ("long=<LONG>","Manually set GPS longitude"),
                                     ("port=<port>","Port GPSD is running on. Default 2947")
                                    ]
                }
        return info


    def get_data(self):
        """Ensure data is returned in the form of a SQL row."""
        #e.g of return data - [("tbl_name", [{'var01':99, 'var02':199}]
        rtnData=[]
        while self.data_store:
            rtnData.append(self.data_store.popleft())
        if rtnData:
            return [("gpsd", rtnData)]
        else:
            return []

    @staticmethod
    def get_tables():
        """This function should return a list of table(s)"""

        table = Table('gpsd',MetaData(),
                            Column('systemTime', DateTime, default='' ),
                            Column('time', DateTime, default=''),
                            Column('lat', Numeric(precision=12,scale=9)),
                            Column('lon', Numeric(precision=12,scale=9)),
                            Column('speed', Float()),
                            Column('alt', Float()),
                            Column('epx', Float()),
                            Column('epy', Float()),
                            Column('sunc', Integer, default=0))
        return [table]

if __name__ == "__main__":
    Snoop().start()
