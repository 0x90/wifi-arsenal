#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sqlalchemy as sa
from threading import Thread
import time
import os
from collections import deque
import requests
import json
from includes.jsonify import json_list_to_objs
import base64
from includes.fonts import *

#logging.basicConfig(level=logging.DEBUG)

class Snoop(Thread):
    def __init__(self, **kwargs):
        Thread.__init__(self)
        self.server = kwargs.get('server_url')
        self.sync_freq = int(kwargs.get('sync_freq', 60))
        self.drone = kwargs.get('drone')
        self.key = kwargs.get('key')
        self.RUN = True
        self.data_store = deque()
        self.last_sync = 0

        self.verb = kwargs.get('verbose', 0)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]

        if not self.server:
            logging.error("Please specify a remote server.")
            exit(-1)

        if not self.drone or not self.key:
            logging.error("Please supply drone (--drone) and key (--key) in order to fetch data from the remote server.")
            exit(-1)
   
    def run(self):
        logging.info("Local Sync plugin will pull remote database replica every %d seconds" % self.sync_freq)
        while self.RUN:
            time.sleep(5)

    def is_ready(self):
        """Indicates the module is ready, and loading of next module may commence."""
        return True

    def stop(self):
        """Perform operations required to stop module and return"""
        self.RUN = False

    @staticmethod
    def get_parameter_list():
        """List of paramters that can be passed to the module, for user help output."""
        info = {"info" : "Pull database from remote server and sync it into the local one. Make sure to specify valid --drone and --key options for the remote server.",
                "parameter_list" : [
                                    ("server_url=<url>","URL of server to pull data from. Server plugin should be running on that machine. (e.g. 'http://1.1.1.1:9001/'"),
                                    ("sync_freq=<secs>", "Frequency to pull a full replica of remote database in seconds")
                                    ]
                }
        return info

    def get_data(self):
        base64string = base64.encodestring('%s:%s' % (self.drone, self.key)).replace('\n', '')
        headers = {'content-type': 'application/json',
                   'Z-Auth': self.key, 'Z-Drone': self.drone, 'Authorization':'Basic %s' % base64string}
        rtnData = []
        now = int(os.times()[4])
        if abs(now - self.last_sync) > self.sync_freq:
            try:
                r = requests.get(self.server+"pull/", headers=headers)
            except Exception,e:
                logging.error("Error fetching remote data. Exception was '%s'" % e)
            else:
                if r.status_code == 200:
                    data = json_list_to_objs(r.text)
                    data_len = 0
                    for row in data:
                        rtnData.append( (row['table'], row['data']) )
                        data_len += len(row['data'])
                    if self.verb > 0:
                        logging.info("Plugin %s%s%s pulled %s%d%s records from remote server." % (GR,self.fname,G,GR,data_len,G))
                else:
                    logging.error("Error fetching remote data. Response code was %d"%r.status_code)
            self.last_sync = now    #Success or not, we'll wait another n seconds
        time.sleep(0.5)
        return rtnData

    @staticmethod
    def get_tables():
        """Return the table definitions for this module."""
        return []

if __name__ == "__main__":
    Snoop().start()
