#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
import os
from includes.fonts import *
from includes.mitm import *


class Snoop(Thread):
    """This plugin starts a proxy server."""
    def __init__(self, **kwargs):
        Thread.__init__(self)
        self.data_store = deque(maxlen=1000)

        # Process arguments passed to module
        self.port = int(kwargs.get('port', 8080))
        self.transparent = kwargs.get('transparent', 'false').lower()
        self.verb = kwargs.get('verbose', 0)
        self.fname = os.path.splitext(os.path.basename(__file__))[0]

        config = proxy.ProxyConfig(
            cacert = os.path.expanduser("~/.mitmproxy/mitmproxy-ca.pem"),
            transparent_proxy = dict (showhost=True, resolver = platform.resolver(), sslports = [443, 8443])
        )


        state = flow.State()
        server = proxy.ProxyServer(config, self.port)
        self.m = MyMaster(server, state)


    def run(self):
        logging.info("Plugin %s%s%s started proxy on port %s%s%s" % (GR,self.fname,G,GR,self.port,G))
        self.m.run()

    def is_ready(self):
        #Perform any functions that must complete before plugin runs
        return True

    def stop(self):
        self.m.shutdown()

    @staticmethod
    def get_parameter_list():
        info = {"info" : "This plugin runs a proxy server. It's useful in conjunction with iptables and rogueAP",
                "parameter_list" : [ ("port=<port>","Port for proxy to listen on."),
                                     ("upprox=<ip:port>","Upstream proxy to use."),
                                     ("transparent=[True|False]","Set transparent mode. Default is False")
                                    ] 
                }
        return info


    def get_data(self):
        """Ensure data is returned in the form of a SQL row."""
        #e.g of return data - [("tbl_name", [{'var01':99, 'var02':199}]
        data = self.m.get_logs()
        toReturn = []
        if data:
            for d in data:
                toReturn.append(d)
            return [("web_logs", toReturn)] 
        else:
            return []


    @staticmethod
    def get_tables():
        """This function should return a list of table(s)"""

        table = Table('web_logs',MetaData(),
                              Column('client_ip', String(length=15)),
                              Column('host', String(length=40)),
                              Column('path', String(length=20)),
                              Column('full_url', String(length=20)),
                              Column('method', String(length=20)),
                              Column('port', String(length=20)),
                              Column('timestamp', String(length=20)),
                              Column('useragent', String(length=20)),
                              Column('cookies', String(length=20)),        
                              Column('sunc', Integer, default=0)
                    )

        #TODO: Need to pull MAC address out with mitm to incorporate below.
        table2 = Table('user_agents', MetaData(),
                        Column('mac', String(64), primary_key=True), #Len 64 for sha256
                        Column('userAgent', String(128), primary_key=True, autoincrement=False)) #One device may have multiple browsers

        return [table]

if __name__ == "__main__":
    Snoop().start()
