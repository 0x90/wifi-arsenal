#! /usr/bin/env python

import os
import re
import csv
import time

from netperf import Netperf

def write_to_file(myrtt):
   filename = "%f_rtt.csv" % exp_start
   writecsv = csv.writer(file(filename, 'w'), lineterminator='\n')

   writecsv.writerows(myrtt.rtt)

class RTT(object):
    def __init__(self):
        super(RTT, self).__init__()

        # TAG value
        self.id = 0
        # Local values
        self.rtt = []

    def __repr__(self):
        return "LinkQuality(rtetx=%s)" % (self.rtt)
    
    def __getitem__(self, idx):
        if idx == 0:
            return self.rtt

    def __setitem__(self, idx, val):
        if idx == 0:
            self.rtt = val

    def __len__(self):
        return 1

    def recode(self, timestamp, rtt):
        try:
            self.rtt.append([timestamp, rtt])
            return True

        except ZeroDivisionError:
            return False

    def refresh(self):
        self.rtt = []
        self.id += 1

if __name__=='__main__':
    #ping = Netperf("192.168.100.3")
    #while 1:
    #    timestamp = time.time()
    #    rtt = Netperf.ping('ping -s 1024 -W 1 -c 1 -q %s' % "192.168.100.3", "192.168.100.3")

    myping = Netperf("192.168.100.3")
    myrtt = RTT()

    exp_start = time.time()

    try:
        while (time.time() - exp_start) < 300:
            timestamp = time.time()
            rtt = myping.ping('ping -s 1024 -W 1 -c 2 -q %s' % "192.168.100.3", "192.168.100.3", 1) # timeout = -W * -c

            myrtt.recode(timestamp, rtt)

    except KeyboardInterrupt:
        print "recorded rtt:", myrtt.rtt
        print "past time", time.time() - exp_start

    write_to_file(myrtt)
    
