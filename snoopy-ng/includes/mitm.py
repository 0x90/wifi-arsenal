#!/usr/bin/env python

import os
from libmproxy import proxy, flow, platform
import datetime
import json
from threading import Thread
from collections import deque

class MyMaster(flow.FlowMaster):

    def run(self):
        self.logs = deque()
        try:
            flow.FlowMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, r):
        f = flow.FlowMaster.handle_request(self, r)
        if f:
            r.reply()

            client_ip = r.client_conn.address[0]
            host =  r.host
            path = r.path
            full_url = r.get_url()
            method = r.method
            port = r.port
            timestamp = r.timestamp_start
            useragent = r.headers.get('User-agent')
            if useragent:
                useragent = useragent[0]
            timestamp = datetime.datetime.fromtimestamp(r.timestamp_start)

            cookies = {}
            tmp_cookies = r.get_cookies()
            if tmp_cookies:
                for k, v in tmp_cookies.iteritems():
                    cookies[k] = v[0]
            cookies = json.dumps(cookies)

            log = {"client_ip":client_ip, "host":host, "path":path, "full_url":full_url, \
                    "method":method, "port":port, "timestamp":timestamp, "useragent":useragent, \
                    "cookies":cookies}
            self.logs.append(log)
        return f

    def get_logs(self):
        rtnData=[]
        while self.logs:
            rtnData.append(self.logs.popleft())
        return rtnData

    def handle_response(self, r):
        f = flow.FlowMaster.handle_response(self, r)
        if f:
            r.reply()
        return f

class myProx(Thread):
    def __init__(self):
        Thread.__init__(self)

        config = proxy.ProxyConfig(
            cacert = os.path.expanduser("~/.mitmproxy/mitmproxy-ca.pem"),
            transparent_proxy = dict (showhost=True,resolver = platform.resolver(), sslports = [443, 8443]) #Thanks nmonkee
        )
        state = flow.State()
        server = proxy.ProxyServer(config, 8080)
        self.m = MyMaster(server, state)

    def run(self):
        print "Running on 8080"
        self.m.run()
        print "Done"

    def get_data(self):
        return self.m.get_logs()



if __name__ == "__main__":
    p = myProx()
    p.run()
