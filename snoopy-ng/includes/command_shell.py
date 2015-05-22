#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
from threading import Thread
import base64
import time
import urllib2
import logging
from includes.run_prog import run_program

class CommandShell(Thread):
    def __init__(self, server, drone, key):
        self.server = server
        self.drone = drone
        self.key = key
        self.RUN = True
        Thread.__init__(self)

    def run(self):
        """Check every N seconds if a new command is required to be run"""
        while self.RUN:
            self.fetch_command()
            time.sleep(5)

    #TODO: 1. Use Posts, and probably JSON for commands. Currently using GETs.
    #      2. Launch programs in a separate thread, to avoid blocking
    def fetch_command(self):
        """Poll the server for new commands, execute, and return"""
        base64string = base64.encodestring('%s:%s' % (self.drone, self.key)).replace('\n', '')
        headers = {'content-type': 'application/json',
                   'Authorization':'Basic %s' % base64string}

        checkForCommandURL = self.server + "/cmd/droneQuery"
        sendCommandOutputURL = self.server + "/cmd/droneResponse"
        try:
            req = urllib2.Request(checkForCommandURL, headers=headers)
            response = urllib2.urlopen(req)

            if response:
                command = response.read()
                if command != "":
                    logging.debug("Running command '%s'" % command)
                    outcome = run_program(command)
                    response_data = urllib.urlencode({'command':command, 'output': outcome } )   
                    req = urllib2.Request(sendCommandOutputURL + "?" + response_data, headers=headers)
                    response = urllib2.urlopen(req)
        except Exception,e:
            logging.error(e)

    def stop(self):
        self.RUN = False

if __name__ == "__main__":
    CommandShell().start()
