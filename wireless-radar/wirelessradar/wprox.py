#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2014, stf - AGPLv3+

# start like:
# airmon-ng start wlan0
# ifconfig wlan0 down
# ./wprox.py

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

def tointrange(data):
    return ",".join("-".join(map(str,(g[0],g[-1])[:len(g)]))
                   for g in (list(x)
                             for _,x in groupby(data, lambda x,c=count(): next(c)-x)))

class ChanSniffer():
    def __init__(self, interface, freq = "2.424GHz" , timeout = 15, verbose=True):
        self.interface = interface
        self.verbose = verbose
        self.freq = freq
        self.peers = {}
        self.lastseen = None
        self.lastshown = None
        self.end_sniffing = False
        self.timeout = timeout

    def run(self, freq = None, timeout = None):
        self.end_sniffing = False
        if freq:
            self.freq = freq
        if timeout:
            self.timeout = timeout

        if self.timeout:
            self.lastseen = time.time()
        try:
            Wireless(self.interface).setFrequency(self.freq)
        except IOError:
            print >>sys.stderr, traceback.format_exc()
            print >>sys.stderr, "meh"
            return
        if self.verbose:
            self.lastshown = time.time()
            print >>sys.stderr, "listening on %s chan: %s (%s)" % (self.interface, chanmap[self.freq[0]+self.freq[2:5]], self.freq)
        while self.lastseen and self.timeout and self.lastseen+self.timeout>time.time() and not self.end_sniffing:
            sniff(iface=self.interface, prn=self.handler, timeout=self.timeout, store=0, stop_filter=self.stop_sniffing)
        return self.peers

    def siglevel(self, packet):
        return -(256-ord(packet.notdecoded[-4:-3]))

    def addseen(self, k, p):
        try:
            self.peers[k]['seen'].append({'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                            'ts': time.time(),
                                            'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100})
        except:
            self.peers[k]['seen']= [{'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                       'ts': time.time(),
                                       'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100}]

    def newdev(self, k, t, p):
        self.peers[k] = {'type': t,
                         'ssids': [repr(p.info)],
                         'seen': [{'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                   'ts': time.time(),
                                   'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100}]}
        if self.timeout: self.lastseen=time.time()

    def adddev(self, k, p):
        try:
            self.peers[k]['ssids'].append(repr(p.info))
        except KeyError:
            self.peers[k]['ssids']=[repr(p.info)]

        self.addseen(p.addr2, p)
        if self.timeout: self.lastseen=time.time()


    def newpeer(self, peer, other, t, p):
        self.peers[peer] = {'type': t,
                            'peers': other,
                            'seen': [{'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                      'ts': time.time(),
                                      'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100}]}
        if self.timeout: self.lastseen=time.time()

    def addpeer(self, dev, peer, p):
        try:
            self.peers[dev]['peers'].append(peer)
        except KeyError:
            self.peers[dev]['peers']=[peer]

        self.addseen(p.addr2, p)
        if self.timeout: self.lastseen=time.time()

    def guesstype(self, other, p):
        t = self.peers.get(other,{}).get('type')
        if t:
            if t == 'ap':
                t = 'client'
            else: t = 'ap'
        return t

    def fixtype(self, k, t, p):
        self.peers[k]['type']=t #'client'
        for dev in self.peers[k]['peers']:
            if self.peers[dev]['type'] not in ['ap' if t == 'client' else 'client', None]:
                print >>sys.stderr, "[pff] type already set", dev, self.peers[dev]['type']
            self.peers[dev]['type']='ap' if t == 'client' else 'client'

    def handler(self, p):
        if p.haslayer(Dot11):
            if p.type == 0:
                if p.subtype in (0,2,4):
                    if p.addr2 not in self.peers:
                        #print "[new] %s %s\t%s" % (p.addr2.upper(),
                        #                           repr(p.info),
                        #                           OUI(p.addr2[:8].replace(':','-')).registration().org)
                        self.newdev(p.addr2, 'client', p)
                    elif repr(p.info) not in self.peers[p.addr2].get('ssids',[]):
                        #print "[add] %s %s\t%s" % (p.addr2.upper(),
                        #                                    repr(p.info),
                        #                                    OUI(p.addr2[:8].replace(':','-')).registration().org)
                        self.adddev(p.addr2, p)
                    else:
                        self.addseen(p.addr2, p)
                    if not self.peers[p.addr2]['type']:
                        self.fixtype(p.addr2, 'client',p)
                elif p.subtype == 8: # beacon
                    if p.addr2 not in self.peers:
                        #print "{new} %s %s\t%s" % (p.addr2.upper(),
                        #                           repr(p.info),
                        #                           OUI(p.addr2[:8].replace(':','-')).registration().org)
                        self.newdev(p.addr2, 'ap', p)
                    elif repr(p.info) not in self.peers[p.addr2].get('ssids',[]):
                        #print "{add} %s %s\t%s" % (p.addr2.upper(),
                        #                           repr(p.info),
                        #                           OUI(p.addr2[:8].replace(':','-')).registration().org)
                        self.adddev(p.addr2, p)
                    else:
                        self.addseen(p.addr2, p)
                    if not self.peers[p.addr2]['type']:
                        self.fixtype(p.addr2, 'ap',p)
            if p.type == 2:
                if (p.addr1.lower() not in ['ff:ff:ff:ff:ff:ff',        # broadcast
                                            '01:00:0c:cc:cc:cd',        # PVSTP+ BPDU
                                            '01:00:0c:cc:cc:cc',        # cisco discovery protocol
                                            '01:40:96:ff:ff:ff',        # IAPP multicast
                                            '01:80:c2:00:00:00',        # STP multicast
                                            '01:80:c2:00:00:0e',        # Link Layer Discovery Protocol
                                            '01:80:c2:00:00:03',        #
                                            '01:80:c2:00:00:00',] and   # lldp end
                    not p.addr1.startswith('33:33') and   # ipv6 multicast
                    p.addr1[:8] not in ['02:00:5e',       # Modified EUI-64 unicast identifier
                                        '01:00:5e',       # multicast
                                        '00:00:5e']):     # unicast
                    dst = p.addr1
                else:
                    dst = None
                if p.addr2 not in self.peers:
                    t = self.guesstype(dst, p)
                    self.newpeer(p.addr2, [dst] if dst else [], t, p)
                elif self.peers[p.addr2]['seen'][-1]['ts']+0.2<time.time():
                    self.addseen(p.addr2, p)
                if dst:
                    if dst not in self.peers:
                        t = self.guesstype(p.addr2, p)
                        self.newpeer(dst, [p.addr2], t, p)
                    if dst not in self.peers[p.addr2].get('peers',[]):
                        self.addpeer(p.addr2, dst, p)
                        #print "<con> %s %s <-> %s %s" % (p.addr2, self.peers[p.addr2], dst, self.peers[dst])

                        # deauth to see roles?
                        #sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())
                    if p.addr2 not in self.peers[dst].get('peers',[]):
                        self.addpeer(dst, p.addr2, p)

            if self.lastseen and self.timeout and self.lastseen+self.timeout<time.time():
                self.end_sniffing=True
            if self.verbose and self.lastshown+2<time.time():
                print >>sys.stderr, '-' * 138
                print >>sys.stderr, self.display()
                print >>sys.stderr, "listening on %s chan: %s (%s)" % (self.interface, chanmap[self.freq[0]+self.freq[2:5]], self.freq)
                self.lastshown = time.time()

    def stop_sniffing(self, pkt):
        return self.end_sniffing

    def rfstats(self, data):
        count = len(data)
        mx = max(x['rssi'] for x in data)
        mn = min(x['rssi'] for x in data)
        avg = sum(x['rssi'] for x in data) / count
        sprd = mx - mn
        chan = sorted(set(x['chan'] for x in data))
        return u"[%-18s] %4s %4s %4s %4s %2s [%-5s]" % (tointrange(chan),
                                                        count,
                                                        mx,
                                                        mn,
                                                        avg,
                                                        sprd,
                                                        bar(100+avg, 70, 5))

    def print_client(self, k, v):
        if v['type']!='client':
            return '[wtf] type is not client %s %s' % (k, v)
        try:
            vendor = OUI(k[:8].replace(':','-')).registration().org
        except:
            vendor = ''
        if len(vendor)>20:
            vendor = "%s..." % vendor[:20]
        flags=''.join([flagmap.get(k[:8], ''), flagmap36.get(k[:13], '')])
        return "%s %-23s %s %-3s %s" % (k,
                                        vendor,
                                        self.rfstats(v['seen']),
                                        flags,
                                        ', '.join(v.get('ssids',[])))

    def display(self):
        shown = set()
        res=["typ AP SSID*                      MAC               vendor"
             "                  channels              cnt  max  min  avg"
             "  sp rssi   flg attempts"] # the header is just one long string!!!
        for k, v in sorted(self.peers.items(),key=lambda (k,v): len(v.get('peers',[])), reverse=True):
            if v['type']!='ap': continue
            try:
                vendor = OUI(k[:8].replace(':','-')).registration().org[:20]
            except:
                vendor = ''
            if len(vendor)>20:
                vendor = "%s..." % vendor[:20]
            flags=''.join([flagmap.get(k[:8], ''), flagmap.get(k[:13], '')])
            res.append("AP %-30s %s %-23s %s %-3s" % (', '.join(v.get('ssids',[])),
                                                      k,
                                                      vendor,
                                                      self.rfstats(v['seen']),
                                                      flags))
            for client in sorted(v.get('peers',[]), lambda _,v1: len(self.peers[v1].get('ssids',[])) ,reverse=True):
                res.append("   %-30s %s" % (', '.join(v.get('ssids',[])), self.print_client(client, self.peers[client])))
                shown.add(client)

        for k, v in self.peers.items():
            if v['type']!='client' or k in shown: continue
            res.append("CL %s %s" % (' '*30, self.print_client(k,v)))

        for k, v in self.peers.items():
            if v['type']!='unknown': continue
            res.append("NA %s <-> %s" % (k, v.get('peers')))
        return '\n'.join(res)

flagmap={"00:02:D1": "C", # vivotek ip cam
         "00:1F:92": "C", # videoiq
         "00:0D:40": "C", # verint loronix video solutions
         "00:1B:C7": "C", # starvedia
         "00:30:F4": "C", # stardot
         "5C:F2:07": "C", # speco technologies
         "18:D9:49": "C", # qvis labs
         "00:04:29": "C", # Pixord Corporation
         "18:52:53": "C", # Pixord Corporation
         "00:04:7D": "C", # pelco
         "00:03:C5": "C", # mobotix
         "18:4E:94": "C", # messoa
         "00:0F:FC": "C", # merit li-lin
         "00:50:1A": "C", # iqinvsion
         "00:13:9B": "C", # ioimage
         "44:19:B6": "C", # hikvision
         "C0:56:E3": "C", # hikvision
         "60:9A:A4": "C", # GVI Security
         "00:0B:82": "C", # grandstream
         "00:13:E2": "C", # geovision
         "00:1E:81": "C", # cnb technology
         "00:1C:B8": "C", # cbc ganz
         "00:18:85": "C", # avigilon
         "00:40:8C": "C", # axis
         "AC:CC:8E": "C", # axis
         "00:1A:07": "C", # arecont
         "00:0F:7C": "C", # acti
         "00:1D:1A": "C", # ovislink
         # drone vendors
         '90:03:B7': "D", # parrot
         'A0:14:3D': "D", # parrot
         '00:12:1C': "D", # parrot
         '00:26:7E': "D", # parrot
        }

flagmap36={"00:50:C2:A9:8": "C", # sentry360
           "00:50:C2:F5:A": "C", # sentry360
           "40:D8:55:09:3": "C", # sentry360
           "40:D8:55:09:C": "C", # sentry360
           "00:50:C2:3B:6": "C", # arecont
}

def main():
    iwrange = Iwrange(sys.argv[1])
    if iwrange.errorflag:
        print (iwrange.errorflag, iwrange.error)
        sys.exit(1)

    cs=ChanSniffer(sys.argv[1])
    for freq in sorted(iwrange.frequencies):
        #if freq > 3000000000: continue
        #print str(freq/1000000), chanmap[str(freq/1000000)]
        cs.run(freq="%.3fGHz" % (freq/1000000000.0),timeout=23)
    print cs.display().encode('utf8')

if __name__ == "__main__":
    main()
