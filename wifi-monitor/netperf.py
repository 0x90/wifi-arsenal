#! /usr/bin/env python

import subprocess
import re
import os

template1 = "packets transmitted, (\d+) received, (\d)% packet loss, time (\d+)ms"
template2 = "rtt min/avg/max/mdev = (\d+.\d*)/(\d+.\d*)/(\d+.\d*)/(\d+.\d*) ms"

class Netperf(object):
    def __init__(self, addr):
        super(Netperf, self).__init__()

        self.addr = addr
        self.sts = 0

    def run(self, cmd, arg):
        #self.sts = subprocess.call([cmd, opt, arg], shell=False)
        self.sts = subprocess.Popen(cmd + " " + arg, shell=True)
        print "Netperf: '%s %s ' " %  (cmd, arg)

    def status(self):
        if self.sts == 0:
            return 1
        else:
            return 0


    def ping(self, cmd, daddr, timeout):
        skipped = True # skipped

        po = os.popen(cmd) # 1s
        line = po.readline()

        if not line:
            print "in ping_test(%s): ping_test timeout." % daddr 
            return 100

        while line:
            line = line.strip()
            if skipped:
                if line == "--- %s ping statistics ---" % daddr:
                    skipped = False
                line = po.readline()
                continue

            line1 = line
            line2 = po.readline()
            break

        #extract results of ping
        r1 = re.compile(template1)
        m1 = r1.search(line1)

        if m1 == None:
            print "in ping_test(%s): ping_test failed." % daddr 
            return timeout

        received = float(m1.group(1))
        dropped = float(m1.group(2))

        r2 = re.compile(template2)
        m2 = r2.search(line2)
        min = float(m2.group(1))
        ave = float(m2.group(2))
        max = float(m2.group(3))
        dev = float(m2.group(4))

        #print "%.2f / %.2f" % (received, received + dropped)
        #print "min: %.2f, ave: %.2f, max: %.2f" % (min, ave, max)

        print "in ping_test(%s): ping_test done." % daddr
        #return (received + dropped) / received * ave
        return ave
