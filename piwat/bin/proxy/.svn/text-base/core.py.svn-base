"""
  Copyright notice
  ================
  
  Copyright (C) 2011
      Roberto Paleari     <roberto.paleari@gmail.com>
      Alessandro Reina    <alessandro.reina@gmail.com>
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  HyperDbg is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
"""

import SocketServer
import BaseHTTPServer
import socket
import threading
import httplib
import time
import os
import urllib
import ssl
import copy

from history import *
from http import *
from https import *
from logger import Logger

DEFAULT_CERT_FILE = "./cert/ncerts/proxpy.pem"

proxystate = None

class ProxyHandler(SocketServer.StreamRequestHandler):
    def __init__(self, request, client_address, server):
        self.peer = False
        self.keepalive = False
        self.target = None

        # Just for debugging
        self.counter = 0
        self._host = None
        self._port = 0

        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)
    
    def createConnection(self, host, port):
        global proxystate

        if self.target and self._host == host:
            return self.target

        try:
            # If a SSL tunnel was established, create a HTTPS connection to the server
            if self.peer:
                conn = httplib.HTTPSConnection(host, port)
            else:
                # HTTP Connection
                conn = httplib.HTTPConnection(host, port)
        except HTTPException as e:
            proxystate.log.debug(e.__str__())

        # If we need a persistent connection, add the socket to the dictionary
        if self.keepalive:
            self.target = conn

        self._host = host
        self._port = port
            
        return conn

    def sendResponse(self, res):
        self.wfile.write(res)

    def finish(self):
        if not self.keepalive:
            if self.target:
                self.target.close()
            return SocketServer.StreamRequestHandler.finish(self)

        # Otherwise keep-alive is True, then go on and listen on the socket
        return self.handle()

    def handle(self):
        global proxystate

        if self.keepalive:
            if self.peer:
                HTTPSUtil.wait_read(self.request)
            else:
                HTTPUtil.wait_read(self.request)

            # Just debugging
            if self.counter > 0:
                proxystate.log.debug(str(self.client_address) + ' socket reused: ' + str(self.counter))
            self.counter += 1

        try:
            req = HTTPRequest.build(self.rfile)
        except Exception as e:
            proxystate.log.debug(e.__str__() + ": Error on reading request message")
            return
            
        if req is None:
            return

        # Delegate request to plugin
        req = ProxyPlugin.delegate(ProxyPlugin.EVENT_MANGLE_REQUEST, req.clone())

        # if you need a persistent connection set the flag in order to save the status
        if req.isKeepAlive():
            self.keepalive = True
        else:
            self.keepalive = False
        
        # Target server host and port
        host, port = ProxyState.getTargetHost(req)
        
        if req.getMethod() == HTTPRequest.METHOD_GET:
            res = self.doGET(host, port, req)
            self.sendResponse(res)
        elif req.getMethod() == HTTPRequest.METHOD_POST:
            res = self.doPOST(host, port, req)
            self.sendResponse(res)
        elif req.getMethod() == HTTPRequest.METHOD_CONNECT:
            res = self.doCONNECT(host, port, req)

    def _request(self, conn, method, path, params, headers):
        global proxystate
        conn.putrequest(method, path, skip_host = True, skip_accept_encoding = True)
        for header,v in headers.iteritems():
            # auto-fix content-length
            if header.lower() == 'content-length':
                conn.putheader(header, str(len(params)))
            else:
                for i in v:
                    conn.putheader(header, i)
        conn.endheaders()

        if len(params) > 0:
            conn.send(params)

    def doRequest(self, conn, method, path, params, headers):
        global proxystate
        try:
            self._request(conn, method, path, params, headers)
            return True
        except IOError as e:
            proxystate.log.error("%s: %s:%d" % (e.__str__(), conn.host, conn.port))
            return False

    def doGET(self, host, port, req):
        conn = self.createConnection(host, port)
        if not self.doRequest(conn, "GET", req.getPath(), '', req.headers): return ''
        # Delegate response to plugin
        res = self._getresponse(conn)
        res = ProxyPlugin.delegate(ProxyPlugin.EVENT_MANGLE_RESPONSE, res.clone())
        data = res.serialize()
        return data

    def doPOST(self, host, port, req):
        conn = self.createConnection(host, port)
        params = urllib.urlencode(req.getParams(HTTPRequest.METHOD_POST))
        if not self.doRequest(conn, "POST", req.getPath(), params, req.headers): return ''
        # Delegate response to plugin
        res = self._getresponse(conn)
        res = ProxyPlugin.delegate(ProxyPlugin.EVENT_MANGLE_RESPONSE, res.clone())
        data = res.serialize()
        return data

    def doCONNECT(self, host, port, req):
        global proxystate

        socket_req = self.request
        certfilename = DEFAULT_CERT_FILE
        socket_ssl = ssl.wrap_socket(socket_req, server_side = True, certfile = certfilename, 
                                     ssl_version = ssl.PROTOCOL_SSLv23, do_handshake_on_connect = False)

        HTTPSRequest.sendAck(socket_req)
        
        host, port = socket_req.getpeername()
        proxystate.log.debug("Send ack to the peer %s on port %d for establishing SSL tunnel" % (host, port))

        while True:
            try:
                socket_ssl.do_handshake()
                break
            except (ssl.SSLError, IOError):
                # proxystate.log.error(e.__str__())
                return

        # Switch to new socket
        self.peer    = True
        self.request = socket_ssl

        self.setup()
        self.handle()

    def _getresponse(self, conn):
        try:
            res = conn.getresponse()
        except httplib.HTTPException as e:
            proxystate.log.debug(e.__str__())
            # FIXME: check the return value into the do* methods
            return None

        body = res.read()
        if res.version == 10:
            proto = "HTTP/1.0"
        else:
            proto = "HTTP/1.1"

        code = res.status
        msg = res.reason

        res = HTTPResponse(proto, code, msg, res.msg.headers, body)

        return res

class ThreadedHTTPProxyServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class ProxyServer():    
    def __init__(self, init_state):
        global proxystate
        proxystate = init_state
        self.proxyServer_port = proxystate.listenport
        self.proxyServer_host = proxystate.listenaddr

    def startProxyServer(self):
        global proxystate
        
        self.proxyServer = ThreadedHTTPProxyServer((self.proxyServer_host, self.proxyServer_port), ProxyHandler)

        # Start a thread with the server (that thread will then spawn a worker
        # thread for each request)
        server_thread = threading.Thread(target = self.proxyServer.serve_forever)
    
        # Exit the server thread when the main thread terminates
        server_thread.setDaemon(True)
        proxystate.log.info("Server %s listening on port %d" % (self.proxyServer_host, self.proxyServer_port))
        server_thread.start()

        while True:
            time.sleep(0.1)

    def stopProxyServer(self):
        self.proxyServer.shutdown()

class ProxyState:
    def __init__(self, port = 8080, addr = "0.0.0.0"):
        # Configuration options, set to default values
        self.plugin     = ProxyPlugin()
        self.listenport = port
        self.listenaddr = addr
        self.dumpfile   = None

        # Internal state
        self.log        = Logger()
        self.history    = HttpHistory()
        self.redirect   = None

    @staticmethod
    def getTargetHost(req):
        global proxystate
        # Determine the target host (check if redirection is in place)
        if proxystate.redirect is None:
            target = req.getHost()
        else:
            target = proxystate.redirect

        return target

class ProxyPlugin:
    EVENT_MANGLE_REQUEST  = 1
    EVENT_MANGLE_RESPONSE = 2

    __DISPATCH_MAP = {
        EVENT_MANGLE_REQUEST:  'proxy_mangle_request',
        EVENT_MANGLE_RESPONSE: 'proxy_mangle_response',
        }

    def __init__(self, filename = None):
        self.filename = filename
    
        if filename is not None:
            import imp
            assert os.path.isfile(filename)
            self.module = imp.load_source('plugin', self.filename)
        else:
            self.module = None

    def dispatch(self, event, *args):
        if self.module is None:
            # No plugin
            return None

        assert event in ProxyPlugin.__DISPATCH_MAP
        try:
            a = getattr(self.module, ProxyPlugin.__DISPATCH_MAP[event])
        except AttributeError:
            a = None

        if a is not None:
            r = a(*args)
        else:
            r = None
            
        return r

    @staticmethod
    def delegate(event, arg):
        global proxystate

        # Allocate a history entry
        hid = proxystate.history.allocate()

        if event == ProxyPlugin.EVENT_MANGLE_REQUEST:
            proxystate.history[hid].setOriginalRequest(arg)

            # Process this argument through the plugin
            mangled_arg = proxystate.plugin.dispatch(ProxyPlugin.EVENT_MANGLE_REQUEST, arg.clone())

        elif event == ProxyPlugin.EVENT_MANGLE_RESPONSE:
            proxystate.history[hid].setOriginalResponse(arg)

            # Process this argument through the plugin
            mangled_arg = proxystate.plugin.dispatch(ProxyPlugin.EVENT_MANGLE_RESPONSE, arg.clone())

        if mangled_arg is not None:
            if event == ProxyPlugin.EVENT_MANGLE_REQUEST:
                proxystate.history[hid].setMangledRequest(mangled_arg)
            elif event == ProxyPlugin.EVENT_MANGLE_RESPONSE:
                proxystate.history[hid].setMangledResponse(mangled_arg)

            # HTTPConnection.request does the dirty work :-)
            ret = mangled_arg
        else:
            # No plugin is currently installed, or the plugin does not define
            # the proper method, or it returned None. We fall back on the
            # original argument
            ret = arg

        return ret

