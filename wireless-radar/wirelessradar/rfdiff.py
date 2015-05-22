#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2014, stf - AGPLv3+

# start like:
# ./rfdiff.py newscan oldscan
#
# where newscan and oldscan are the stdouts of different wprox scans

from datetime import datetime
import sys
import netaddr

def load(fn):
    res={}
    with open(fn,'r') as fd:
        for line in fd.readlines()[1:]:
            stats=line[77:]
            idx=stats.find(']')
            mac=line[34:51]
            res[mac] = (mac,                                    # mac
                        line[2:32].strip(),                     # essid
                        'cl' if line[:2] == '  ' else line[:2], # type
                        stats[:idx].strip(),                    # chans
                        int(stats[idx+2:idx+6].strip()),        # count
                        int(stats[idx+7:idx+11].strip()),       # max
                        int(stats[idx+12:idx+16].strip()),      # min
                        int(stats[idx+17:idx+21].strip()),      # avg
                        int(stats[idx+22:idx+24].strip()),      # spread
                        stats[idx+32:idx+36].strip(),           # flags
                        stats.decode('utf8')[idx+36:].strip(),  # attempts
                        line
                        )
    return res

def wskip(rec):
    return rec[7]<-85

def main():
    old=load(sys.argv[1])
    new=load(sys.argv[2])
    
    # deleted
    deleted=set(old.keys()) - set(new.keys())
    if deleted:
        rendered = [old[k][-1][:-1] for k in deleted if not wskip(old[k])]
        if rendered:
            print 'gone\t%s' % '\ngone\t'.join(rendered)
    
    # new
    added=set(new.keys()) - set(old.keys())
    if added:
        rendered = [new[k][-1][:-1] for k in added if not wskip(new[k])]
        if rendered:
            print 'new\t%s' % '\nnew\t'.join(rendered)
    
    # rest
    rest=set(new.keys()) & set(old.keys())
    if rest:
        for k in rest:
            diffs=[]
            id=[]
            #  mac essid type chans count max min avg spread attempts
            if old[k][2]=='CL' and new[k][2]=='cl':
                diffs.append(('connected',old[k][1] or old[k][0],new[k][1] or new[k][0]))
            elif old[k][2]=='cl' and new[k][2]=='CL':
                diffs.append(('disconnected',old[k][1] or old[k][0],new[k][1] or new[k][0]))
            elif old[k][2]=='AP' and new[k][2]=='AP' and old[k][1]!=new[k][1]:
                diffs.append(('essid',old[k][1] or old[k][0],new[k][1] or new[k][0]))
            elif old[k][2]!=new[k][2]:
                diffs.append(('type',old[k][2] or old[k][0],new[k][2] or new[k][0]))
            o=float(old[k][7])
            n=float(new[k][7])
            if min((o,n))/max((o,n)) > 130/100.0:
                diffs.append(('rssi',old[k][7],new[k][7]))
            if diffs:
                print "changed %s\n\t%s" % (new[k][-1][:-1], '\n\t'.join("%s: %s \t -> \t%s" % data for data in  diffs))

if __name__ == "__main__":
    main()
