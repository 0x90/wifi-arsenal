#! /usr/bin/env python

import os
import re
import string

from average import WeightedAverage
from netperf import Netperf

class LinkQuality(object):
    def __init__(self, addr, min, channel):
        super(LinkQuality, self).__init__()

        # TAG value
        self.addr = addr
        self.lq = 10.0

        # Local values
        self.channel = channel
        self.snr = WeightedAverage(100, min) # min = snr_threshold
        self.retry = 0
        self.all = 0
        self.rate = {}
        self.rtetx = []
        self.rtetx2 = []

    def __repr__(self):
        return "LinkQuality(addr=%s, lq=%f, channel=%i, snr=%f, retry=%u, all=%u, rate=%s, rtetx=%s)" % (self.addr, self.lq, self.channel, self.snr.emavalue(0.8), self.retry, self.all, self.rate, self.rtetx)
    
    def __getitem__(self, idx):
        if idx == 0:
            return self.addr
        if idx == 1:
            return self.lq
        if idx == 2:
            return self.channel
        if idx == 3:
            return self.snr
        if idx == 4:
            return self.retry
        elif idx == 5:
            return self.all
        elif idx == 6:
            return self.rate
        elif idx == 7:
            return self.rtetx

    def __setitem__(self, idx, val):
        if idx == 0:
            self.addr = val
        if idx == 1:
            self.lq = val
        if idx == 2:
            self.channel = val
        if idx == 3:
            self.snr = val
        if idx == 4:
            self.retry = val
        elif idx == 5:
            self.all = val
        elif idx == 6:
            self.rate = val
        elif idx == 7:
            self.rtetx = val

    def __len__(self):
        return 8

    def calculate(self, emasnr, timestamp, rtt):
        try:
            tx_loss = float(self.retry) / float(self.all)
            tmp_rtetx = 1.0 / ( 1.0 - tx_loss )

            self.rtetx.append([timestamp, tmp_rtetx, rtt]) # not used since 20081228 -> rtt_measurement.py added
            self.lq = tmp_rtetx

            self.rtetx2.append([timestamp, tmp_rtetx, emasnr])

            return tmp_rtetx

        except ZeroDivisionError:
            return 1.0


    def refresh(self, emasnr, timestamp):
        #print "rtt", rtt
        if self.all > 100: # Data frames = same as ff.tx_frame
            #print "TESTTESTTESTTEST"
            #nf = Netperf("192.168.100.3")
            #tmp_rtt = nf.ping('ping -s 1024 -i 0.01 -W 1 -c 3 -q %s' % "192.168.100.3", "192.168.100.3")
            tmp_rtt = 0.0
            print "rtETX [%s]  : %.2f, rtt : %.2f" % (self.addr, self.calculate(emasnr, timestamp, tmp_rtt), tmp_rtt)
            self.all = 0
            self.retry = 0

            return 1

        return 0
