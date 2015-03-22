#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2014, stf - AGPLv3+

from pythonwifi.iwlibs import Wireless
from datetime import datetime
from launcher import RocketManager
from functools import partial
from operator import itemgetter
import sys, os, time, random

interface='wlan1'

LEFT=3
RIGHT=2
UP=1
DOWN=0

HMAX=3400
VMAX=280

blocks = u' ▁▂▃▄▅▆▇██'

class Scanner():
    def __init__(self, wireless, x=0, y=0):
        self.w=Wireless(wireless)
        self.rm=None
        self.x=x
        self.y=y
        self.aps={}

    def init_launcher(self):
        self.rm=RocketManager()
        self.rm.acquire_devices()

    def step(self,dir,steps=1, sane=False):
        if not self.rm: self.init_launcher()
        c=0
        while c<steps:
            if dir==RIGHT:
                if sane or self.x>0: self.x-=1
                else: break
            elif dir==LEFT:
                if sane or self.x<HMAX: self.x+=1
                else: break
            elif dir==UP:
                if sane or self.y<VMAX: self.y+=1
                else: break
            elif dir==DOWN:
                if sane or self.y>0: self.y-=1
                else: break
            self.rm.launchers[0].start_movement(dir)
            self.rm.launchers[0].stop_movement()
            c+=1
        if c==steps:
            return True

    def home(self):
        if not self.rm: self.init_launcher()
        print "press c-c when in home position"
        while True:
            print s.x
            try:
                s.step(RIGHT,steps=200, sane=True)
            except KeyboardInterrupt:
                self.rm.launchers[0].stop_movement()
                sys.exit(0)

    def scan(self,c=1, cb=None):
        res=[]
        for _ in xrange(c):
            tmp=[]
            for h in self.w.scan():
                try:
                    name=h.essid.decode('utf8')
                except:
                    name=h.bssid
                # TODO add
                # "Quality: Quality ", self.quality.quality
                # "Signal ", self.quality.getSignallevel()
                # "Noise ", self.quality.getNoiselevel()
                # "Encryption:", map(lambda x: hex(ord(x)), self.encode)
                # "Frequency:", self.frequency.getFrequency(), "(Channel", self.frequency.getChannel(self.range), ")"
                record=(self.x,
                        self.y,
                        datetime.now().isoformat(),
                        h.bssid,
                        h.quality.getSignallevel(),
                        name.strip())
                tmp.append(record)
            if cb: tmp=cb(tmp)
            res.extend(tmp)

        # handle callback
        for ap in res:
            # print all scan records
            print u' '.join([unicode(f) for f in ap])
            # remember all entries for later
            self.store(*ap)

        return res

    def store(self, x, y, date, bssid, rssi, name):
        try:
            self.aps[bssid]['rssi'].append((date, int(rssi), int(x), int(y)))
        except:
            self.aps[bssid]={'name': name.strip(),
                             'rssi': [(date, int(rssi), int(x), int(y))]}

    def fasth(self, c=1, steps=10, cb=None, sweeps=1):
        res=[]
        dirs=[LEFT, RIGHT]
        for i in xrange(sweeps):
            while True:
                aps=self.scan(c)
                if cb: aps=cb(aps)
                res.extend(aps)
                if not self.step(dirs[i%2],steps):
                    break
            if self.y==0:
                self.movetoy(VMAX)
            else:
                self.movetoy(0)
        return res

    def apRSSI(self, target, batch):
        # x, y, date, bssid, rssi, name
        data=[item[4] for item in batch if item[3]==target and int(item[4])>-100]
        if data:
            rssi=sum(data)/float(len(data))
            print >>sys.stderr, "%4s %4s %3.2f |%s" % (self.x, self.y, rssi, '▬'*int(rssi+100))
        else:
            print >>sys.stderr, "%4s %4s        |" % (self.x, self.y)
        return batch

    def apCount(self, batch):
        # x, y, date, bssid, rssi, name
        count=len(set([item[3] for item in batch]))
        print >>sys.stderr, "%4s %4s %s %s" % (self.x, self.y, count, '▬'*count)
        return batch

    def stats(self):
        # do some stats on the seen APs
        stats=sorted([(sum([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256'])/len(v['rssi']),
                       max([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256']),
                       min([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256']),
                       max([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256'])-min([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256']),
                       key,
                       v['name'])
                      for key, v in self.aps.items()],
                     reverse=True)
        print >>sys.stderr, "avg mx mn sprd key name"
        for avg, mx, mn, sprd, key, name in stats:
            print >>sys.stderr, key, avg, mx, mn, sprd, self.aps[key]['name']

        for ap in s.ordered(by='dir'):
            print "|%s| %4s %3s %s %s %s %s" % (self.apspark(s.aps[ap[0]]), ap[4], ap[5], ap[2][:19], ap[0], ap[3], ap[1])

    def apspark(self, ap):
        radar=[[0,0] for _ in xrange(20)]
        for item in sorted(ap['rssi'],key=itemgetter(2)):
            radar[int(item[2]/((HMAX+1.0)/20))][0]+=item[1]
            radar[int(item[2]/((HMAX+1.0)/20))][1]+=1
        tmp=[x[0]/x[1] if x[1] else None for x in radar]
        if not [x for x in tmp if x]:
            return "%s" % ' '*20
        tmp=[y or min([x for x in tmp if x])-((max([x for x in tmp if x])-min([x for x in tmp if x]))/8)-1 for y in tmp]
        return "%s" % s.spark(tmp).encode('utf8')

    def load(self,file):
        for line in file.readlines():
            try:
                self.store(*line.split(' ',5))
            except TypeError:
                pass

    def ordered(self, by='dir'):
        if by=='rssi': sortby=3
        else: sortby=4
        return sorted([(ap, data['name'])+max(data['rssi'], key=itemgetter(1))
                       for ap, data in self.aps.items()],
                      key=itemgetter(sortby))

    def spark(self, data):
        lo = float(min(data))
        hi = float(max(data))
        incr = (hi - lo)/(len(blocks)-1) or 1
        return ''.join([(blocks[int((float(n) - lo)/incr)]
                        if n else
                        ' ')
                       for n in data])

    def movetox(self,x):
        dir=LEFT if self.x <= x else RIGHT
        dist=self.x - x if x <= self.x else x - self.x
        self.step(dir,dist)

    def movetoy(self,y):
        dir=UP if self.y <= y else DOWN
        dist=self.y - y if y <= self.y else y - self.y
        self.step(dir,dist)

    def randomdir(self, plane, dir):
        oplane=plane
        odir=dir
        # choose another direction
        while dir==odir and plane==oplane:
            plane=random.randint(0,2)%2
            dir=random.randint(0,1)
        return (plane, dir)

    def lock(self, target):
        # use with - where the param to tail controls how many past scans to consider:
        # cat $(ls -rt logs/*.log | tail -5) | ./wscan.py lock <bssid> >logs/$(date '+%s').log
        top=sorted(self.aps[target]['rssi'], key=itemgetter(1), reverse=True)
        sample_size=30 if len(top)>30 else len(top)
        posx=sum([x[2] for x in top][:sample_size])/sample_size
        posy=sum([x[3] for x in top][:sample_size])/sample_size
        rssi=sum([x[1] for x in top][:sample_size])/sample_size
        # go to last known best position
        print >>sys.stderr, "|%s| %4s %4s %4s" % (self.apspark(self.aps[target]), posx, posy, rssi)
        self.movetox(posx)
        self.movetoy(posy)

        prev=None
        dirs=[[LEFT,RIGHT],[UP,DOWN]]
        plane, dir=self.randomdir(None,None)
        steps=97
        lost=0
        best=None

        try:
            while True:
                # scan a bit
                pop=15

                #samples=[x[4] for x in self.scan(c=pop, cb=partial(self.apRSSI,target)) if x[3]==target]
                samples=self.scan(c=pop)
                self.apRSSI(target, samples)
                # only our own samples
                samples=[x[4] for x in samples if x[3]==target]

                # avg rssi in this direction
                # avg is fixed with missing readings, using -100db
                rssi=(sum(samples)+(-100*(pop-len(samples))))/float(pop)

                if not rssi:
                    if lost>5: break
                    lost+=1
                    if lost==3 and best:
                        # retry from last best position
                        self.movetox(best[1])
                        self.movetoy(best[2])
                        plane,dir=self.randomdir(plane,dir)
                else:
                    lost=0
                # FIXME: more efficient search algo than below

                if best and (int(best[0])-3)>int(rssi):
                    # signal degraded, backtrack
                    # retry from last best position
                    self.movetox(best[1])
                    self.movetoy(best[2])
                    plane,dir=self.randomdir(plane,dir)
                    continue

                if not best or best[0]<rssi:
                    best=(rssi, self.x, self.y)

                if (prev and int(prev)-2>int(rssi)):
                    # signal degraded
                    self.step(dirs[plane][(dir+1)%2], steps/((plane*4)+1))
                    plane,dir=self.randomdir(plane,dir)
                    continue
                prev=rssi

                # wander mindlessly
                if not self.step(dirs[plane][dir], steps/((plane*4)+1)):
                    # we hit some boundary, let's rebound
                    plane,dir=self.randomdir(plane,dir)

        except KeyboardInterrupt:
            pass
        # go home
        self.movetoy(0)
        self.movetox(0)

def main():
    if len(sys.argv)>1:
        if sys.argv[1]=='reset':
            s=Scanner(interface)
            #s.step(DOWN,320,sane=True)
            #s.step(DOWN,175,sane=True)
            s.home()
        elif sys.argv[1]=='load':
            s=Scanner(interface)
            s.load(sys.stdin)
            s.stats()
        elif sys.argv[1]=='lock':
            if not len(sys.argv)>2:
                print >>sys.stderr, "pls supply a bssid for locking"
                sys.exit(1)
            s=Scanner(interface)
            s.load(sys.stdin)
            s.lock(sys.argv[2])
        else:
            # general scan: show rssi graph of all APs
            s=Scanner(interface)
            cb=partial(s.apRSSI,sys.argv[1])
            print >>sys.stderr, 'dir', 'RSSI of', sys.argv[1]
            s.fasth(c=5, steps=97, cb=cb, sweeps=2)
    else:
        s=Scanner(interface)
        print >>sys.stderr, 'dir', 'number of APs'
        s.fasth(c=5, steps=199, sweeps=2, cb=s.apCount)
    
if __name__ == "__main__":
    main()
