#!/usr/bin/python

import web
from web import form
web.config.debug = True
import json
import md5
import time

# Testing mode imports
import pdb
import wifiobjects
import random

urls = (
    '/','view_test'
)

class view_test:
    def randSent(self,len):
        str = ''
        for i in range(len):
            str += chr(random.randint(32,127))
        return str

    def GET(self):
        dict = {}
        for i in range(random.randint(1,3)):
        # Access Points 
            m = md5.new()
            ap = wifiobjects.accessPoint(self.randSent(8))
            m.update(str(ap.fts)+ap.bssid)
            # Attached clients
            for z in range(random.randint(0,3)):
                client = wifiobjects.client(self.randSent(8))
                # probes
                for x in range(random.randint(0,3)):
                    client.updateProbes(self.randSent(8))
                client.bssid = ap
                ap.addClients(client)
            
            dict[m.hexdigest()] = ap.__dict__
        # Unattached Clients
        for y in range(random.randint(0,2)):
            m = md5.new()
            client = wifiobjects.client(self.randSent(8))
            m.update(str(client.fts)+client.mac)
            # Unattached Client Probes
            for x in range(random.randint(0,3)):
       	        client.updateProbes(self.randSent(8))
            dict[m.hexdigest()] = client.__dict__
        
        # Give the JSON-encoded, dictionaried dictionary back
        pdb.set_trace()
        return json.dumps(dict)

    def POST(self):
        pass

if __name__ == "__main__":
    app = web.application(urls,globals())
    app.run()

# WSGI Deployment shit for Apache.
app = web.application(urls, globals(), autoreload=False)
application = app.wsgifunc()

