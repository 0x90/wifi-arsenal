#!/usr/bin/python

import web
from web import form
web.config.debug = True
import json
import md5
import time
import Tool80211
import sys

# Testing mode imports
import pdb
import wifiobjects
import random
import threading

urls = (
    '/','view_test'
)

class view_test:
    def GET(self):
        

    def POST(self):
        pass

class server:
    def __init__(self,card):
        airmonitor = Tool80211.Airview(card)
        airmonitor.start()
        while True:
            self.dict = {}
            bss = airmonitor.apObjects
            clients = airmonitor.clientObjects
            for client in clients.keys():
                if clients[client].bssid is not None:
                    del clients[client]
                else:
                    m = md5.new()
                    clients[client]
                    m.update(str(client.fts)+client.mac)
                    self.dict[m.hexdigest()] = client.__dict__

            for i in bss.keys():
                m = md5.new()
                ap = bss[i]
                m.update(str(ap.fts)+ap.bssid)
                self.dict[m.hexdigest()] = ap.__dict__
    def GET():
        return self.dict

if __name__ == "__main__":
    if len(sys.argv)<=1:
        print "Usage: ./airview_web.py [wifi_interface]"
        exit()

    app = web.application(urls,globals())
    app.run()

# WSGI Deployment shit for Apache.
app = web.application(urls, globals(), autoreload=False)
application = app.wsgifunc()

