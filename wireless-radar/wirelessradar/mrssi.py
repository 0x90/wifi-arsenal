#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2014, stf - AGPLv3+

# start like:
# airmon-ng start wlan0
# ifconfig wlan0 down
# ./mrssi.py mon0 <mac> <channel>

from scapy.all import sniff, Dot11
# pip install git+https://github.com/pingflood/pythonwifi.git
from pythonwifi.iwlibs import Wireless, Iwrange
from netaddr import OUI
import time, traceback, sys
from itertools import count, groupby

chanmap = {"2412": 1, "2417": 2, "2422": 3, "2427": 4, "2432": 5,
           "2437": 6, "2442": 7, "2447": 8, "2452": 9, "2457": 10,
           "2462": 11, "2467": 12, "2472": 13, "2484": 14, "4915": 183,
           "4920": 184, "4925": 185, "4935": 187, "4940": 188, "4945": 189,
           "4960": 192, "4980": 196, "5035": 7, "5040": 8, "5045": 9,
           #"5055": 11, "5060": 12,
           "5080": 16, "5170": 34, "5180": 36,
           "5190": 38, "5200": 40, "5210": 42, "5220": 44, "5230": 46,
           "5240": 48, "5260": 52, "5280": 56, "5300": 60, "5320": 64,
           "5500": 100, "5520": 104, "5540": 108, "5560": 112, "5580": 116,
           "5600": 120, "5620": 124, "5640": 128, "5660": 132, "5680": 136,
           "5700": 140, "5745": 149, "5765": 153, "5785": 157, "5805": 161,
           "5825": 165}
freqmap = { v: k for k, v in chanmap.items()}

def chan2freq(chan):
    return "%.3fGHz" % (float(freqmap[chan])/1000)

def bar(val, mx, size):
    bars=u"▏▎▍▌▋▊▉█"
    width=(val%(mx/size))*(float(len(bars))/(mx/size))
    return (u"█" * int(val/(mx/size))) + (bars[int(width)])

def spark(data):
    blocks = u'▁▂▃▄▅▆▇' #█'
    lo = float(min(data))
    hi = float(max(data))
    incr = (hi - lo)/(len(blocks)-1) or 1
    return ''.join([(blocks[int((float(n) - lo)/incr)]
                     if n else
                     u'▁') #' ')
                    for n in data])

def sparkline(data, size):
    mx = max(x[1] for x in data)
    mn = mx - size
    res = [[] for _ in xrange(size)]
    for elem in data:
        for i in xrange(size+1):
            if mn+i>=elem[1]:
                res[i-1].append(elem[0])
                break
    hist = [(sum(x)/len(x)) if len(x)>0 else -100 for x in res]
    return "%-4s %s %-4s" % (min(hist),spark(hist), max(hist))

class MacRSSI():
    def __init__(self, interface, mac, freq):
        self.interface = interface
        self.mac = mac.lower()
        self.freq = int(freq)
        try:
            if self.freq<1000:
                self.freq = chan2freq(self.freq)
        except:
            self.freq = freq
        self.hist = []
        self.hist_size = 40

    def run(self):
        try:
            Wireless(self.interface).setFrequency(self.freq)
        except IOError:
            print >>sys.stderr, traceback.format_exc()
            print >>sys.stderr, "meh"
            return
        self.hist = []
        print >>sys.stderr, "looking for %s on %s chan: %s (%s)" % (self.mac, self.interface, chanmap[self.freq[0]+self.freq[2:5]], self.freq)
        sniff(iface=self.interface, prn=self.handler, store=0)

    def siglevel(self, packet):
        return -(256-ord(packet.notdecoded[-4:-3]))


    def handler(self, p):
        if p.haslayer(Dot11):
            # Check to make sure this is a management frame (type=0) and that
            # the subtype is one of our management frame subtypes indicating a
            # a wireless client
            if p.addr2 and p.addr2.lower() == self.mac:
                rssi = self.siglevel(p) if self.siglevel(p)!=-256 else -100
                now = time.time()
                self.hist.append((rssi, now))
                for i, x in enumerate(self.hist):
                    if x[1]>now-self.hist_size:
                        self.hist = self.hist[i:]
                        break
                rbar = bar(100+rssi, 100, self.hist_size)
                print "\r%-4s %s%s| %s        " % (rssi, rbar,' '*(40-len(rbar)), sparkline(self.hist,self.hist_size)),

def main():
    cs=MacRSSI(sys.argv[1], sys.argv[2], sys.argv[3])
    cs.run()

if __name__ == "__main__":
    main()
