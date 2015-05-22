#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import datetime
import collections
import logging
import os
from includes.fonts import *

def _newProxTest(ident):
    """Determine if a new session should be started. Should be overriden"""
    print "True!"
    return True

class prox:
    """Proximity session for arbitary observations."""

    def __init__(self,proxWindow=300, identName="ident", pulseName="numPulses", newProxFunc=_newProxTest, callerName='Unknown', verb=0):
        """
            proxWindow: sets the idletime before a new session is created
            newProxFunc: The function to test (beyond time) if a new session should be created
        """
        self.proxWindow = proxWindow
        self.currentProxSessions = {}
        self.closedProxSessions = collections.deque()
        self.mostRecentPulse = 0
        self.identName = identName #e.g. "mac", "hostname", etc
        self.pulseName = pulseName #e.g. num_probes, cookies, etc
        self.newProxFunc = newProxFunc
        self.callerName = callerName #For debug output
        self.verb = verb #Verbosity for debugging

    def pulse(self,ident, time=None):
        """ident is a variable that uniquely identifies a session. It
            can be a single value, or an array/tuple/etc"""
        if not time:
            time = datetime.datetime.now()
        self.mostRecentPulse = time

        # New session
        if ident not in self.currentProxSessions:
            self.currentProxSessions[ident] = [time, time, 1, 0]
            # Format is firstObser, lastObser, numPules, Sunc
            if self.verb > 1:
                logging.info("Sub-plugin %s%s%s observed new %s: %s%s%s" % (GR,self.callerName,G,self.identName,GR,ident,G))
        else:
            # Check if the session has expired
            firstObs = self.currentProxSessions[ident][0]
            lastObs = self.currentProxSessions[ident][1]
            numPulses = self.currentProxSessions[ident][2]
            if (time - lastObs).seconds >= self.proxWindow: #and self.newProxFunc(ident):
                self.closedProxSessions.append((ident, firstObs, lastObs, numPulses)) #Terminate old prox session
                self.currentProxSessions[ident] = [time, time, 1, 0] #Create new prox session
            else:
                self.currentProxSessions[ident][2] += 1     # Count number of pulses
                self.currentProxSessions[ident][1] = time
                self.currentProxSessions[ident][3] = 0 #Mark as require db sync

    def getNumProxs(self):
        return len(self.currentProxSessions) + len(self.closedProxSessions)

    def getProxs(self, timeStamp = None):
        """Return all proximity sessions that have not yet been reported. Calling this will
            empty local data structures. Use most recent pulse timestamp to determine expiration
            status, unless a time value is passed for time."""
        # First check if expired, if so, move to closed.
        # Use the most recent ident received as a timestamp.
        todel=[]
        data=[]
        if not timeStamp:
            t = self.mostRecentPulse
        else:
            t=timeStamp
        for ident,value in self.currentProxSessions.iteritems():
            firstObs=value[0]
            lastObs=value[1]
            numPulses=value[2]
            #t=self.mostRecentPulse
            if (t - lastObs).seconds >= self.proxWindow:
                self.closedProxSessions.append((ident,firstObs,t,numPulses))
                todel.append(ident)
        for ident in todel:
            del(self.currentProxSessions[ident])
        #1. Open Prox Sessions
        tmp_open_prox_sessions=[]
        for ident,value in self.currentProxSessions.iteritems():
            firstObs,lastObs,numPulses=value[0], value[1], value[2]
            #firstObs,lastObs = datetime.datetime.fromtimestamp(firstObs), datetime.datetime.fromtimestamp(lastObs)
            if value[3] == 0:
                tmp_open_prox_sessions.append({self.identName:ident,"first_obs":firstObs,"last_obs":lastObs,self.pulseName:numPulses})
        #2. Closed Prox Sessions
        tmp_closed_prox_sessions=[]
        for i in range(len(self.closedProxSessions)):
            ident, firstObs, lastObs, numPulses=self.closedProxSessions.popleft()
            #firstObs, lastObs = datetime.datetime.fromtimestamp(firstObs), datetime.datetime.fromtimestamp(lastObs)
            tmp_closed_prox_sessions.append( {self.identName:ident,"first_obs":firstObs,"last_obs":lastObs,self.pulseName:numPulses})#, "drone":self.drone, "location":self.location} )
        if( len(tmp_open_prox_sessions+tmp_closed_prox_sessions) > 0 ):
            #Set flag to indicate data has been fetched:
            for i in tmp_open_prox_sessions:
                ident=i[self.identName]
                self.currentProxSessions[ident][3]=1 #Mark it has having been retrieved, so we don't resend until it changes

            proxSess = tmp_open_prox_sessions+tmp_closed_prox_sessions
            return proxSess
