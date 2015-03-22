#!/usr/bin/python
import sys, os
import csv
import math
import numpy
from math import sqrt
sys.path.append('/Users/stephen/Documents/wifi')
sys.path.append('/home/nm/work/wifi')
os.environ['DJANGO_SETTINGS_MODULE'] = 'wifi.settings'
from django.db import models
from wifi.models import *
from operator import itemgetter, attrgetter

LAMBDA = 1.0
# Parameters for confidence value calculation
stdBaselineX = 2.54
stdBaselineY = 2.54
baselineRedpin = 10
P = 5
Q = 5
R = 5/3


dist = {}
ncaps = {}
nnaps = {}
scores = {}
ncap_list = {}
algtype = "redpin"

SIGNAL_CONTRIBUTION = 1
SIGNAL_PENALTY_THRESHOLD = 10
SIGNAL_GRAPH_LEVELING = 0.2




def redpin_score(rssi1, rssi2):
    base = rssi1
    diff = abs(rssi1-rssi2)
    x = diff / abs(base)
    y = 0
    if (x > 0.0):
        y = 1/x
        t = SIGNAL_PENALTY_THRESHOLD/base
        y -= 1/t
        y = y*SIGNAL_GRAPH_LEVELING
        return y
    return SIGNAL_CONTRIBUTION



def measure(reading):
    #print len(reading)
    bss_reading = {}
    fps = Fingerprint.objects.all()
    for r in reading:
        if int(r["rssi"]) > -90:
            a = r["mac_addr"].lower()
            last_bytes = a.split("-")[4] + "-" + a.split("-")[5]
            bss_reading[last_bytes] = r["rssi"]
            
    for key in bss_reading:
        bss_set = Bss.objects.filter(mac_addr__iendswith=key)
        for b in bss_set:
            signals = SignalReading.objects.filter(bss=b, bss__channel__lte=9000, rssi__gte=-90)
            for s in signals:
                if not dist.has_key(s.fingerprint.id):
                    dist[s.fingerprint.id] = 0.0
                if not scores.has_key(s.fingerprint.id):
                    scores[s.fingerprint.id] = 0.0
                if not ncaps.has_key(s.fingerprint.id):
                    ncaps[s.fingerprint.id] = 0
                if not ncap_list.has_key(s.fingerprint.id):
                    ncap_list[s.fingerprint.id] = ""
                ncaps[s.fingerprint.id] += 1
                #ncap_list[f.pk] += s.bss.mac_addr + ": " + s.bss.ssid + ","
                curr_score = redpin_score(float(bss_reading[key]), float(s.rssi))
                scores[s.fingerprint.id] += curr_score
        


if len(sys.argv) < 2:
	print "usage: " + sys.argv[0] + " input_file "
	sys.exit()

if len(sys.argv) > 2:
    if sys.argv[2] == "nnss":
        algtype = "nnss"




print "matching data from "  + sys.argv[1]
fingerprint = {}
with open(sys.argv[1],'rU') as f:
    reader=csv.reader(f,delimiter='\t')
    #for tstamp, beacon, bssid, rssi, freq, ssid in reader:
    for c in reader:
        if len(c) >= 7:
            hwtstamp, tstampms, tstamp, bssid, rssi, freq, ssid = c[0:7]
            newssid = ""
            for char in ssid:
                if ord(char) >= 32 and ord(char) < 128:
                    newssid += char
            ssid = newssid
        elif len(c) == 6:
            hwtstamp, tstampms, tstamp, bssid, rssi, freq = c
            ssid="HIDDEN"
       
        if not fingerprint.has_key(tstamp):
            fingerprint[tstamp] = []
        bss = {}
        bss["mac_addr"] = bssid
        bss["rssi"] = rssi
        bss["chan"] = freq
        bss["ssid"] = ssid
        if int(rssi) > -90:
            fingerprint[tstamp].append(bss)

hall_cluster = Cluster.objects.get(pk=1)

for f in fingerprint:
    dist = {}
    ncaps = {}
    nnaps = {}
    scores = {}
    tmpres = {}
    results = []
    measure(fingerprint[f])
    if algtype == "redpin":
        print "X,Y,RSSI score,NCAP,NNAP,REDPIN SCORE"
        for key in scores:
            num_readings = len(SignalReading.objects.filter(fingerprint = key, bss__channel__lte=9000, rssi__gte=-90))
            num_aps = max(num_readings, len(fingerprint[f]))
            #print "len: " + str(len(fingerprint[f]))
            nnaps[key] = num_aps - ncaps[key]
            fp = Fingerprint.objects.get(pk=key)
            total_score = 0.2*scores[key] + 1.0*ncaps[key] - 0.4*nnaps[key]
            tmpres = {}
            tmpres["x_coord"] = fp.x_coord
            tmpres["y_coord"] = fp.y_coord
            tmpres["dist"] = scores[key]
            tmpres["ncaps"] = ncaps[key]
            tmpres["nnaps"] = nnaps[key]
            tmpres["redpin_score"] = total_score
            results.append(tmpres)

        
        sorted_res = sorted(results, key=lambda k: k["redpin_score"], reverse=True)

        sum_of_redpin = 0
        stdX = 0
        stdY = 0
        i = 0
        bcenter_x = 0
        bcenter_y = 0
        for res in sorted_res:
            if i < 5:
                sum_of_redpin += res["redpin_score"]
                bcenter_x += res["x_coord"]
                bcenter_y += res["y_coord"]
            i += 1
            print str(res["x_coord"]) + "," + str(res["y_coord"]) + "," + str(res["dist"]) + "," + str(res["ncaps"]) + "," + str(res["nnaps"]) + "," + str(res["redpin_score"])
        bcenter_x /= 5.0
        bcenter_y /= 5.0
        avg_redpin = sum_of_redpin / 5.0
        for j in range(5):
            curr_x = sorted_res[j]["x_coord"]
            curr_y = sorted_res[j]["y_coord"]
            #distances_to_barycenter.append(euclidean_dis(curr_x, curr_y, bcenter_x, bcenter_y))
        avg_dis = 0
        #for k in range(5):
        #    avg_dis += distances_to_barycenter[k]
        #avg_dis /= 5.0
        #confidence = avg_redpin - LAMBDA * avg_dis
        #print "END RESULT: " + str(bcenter_x) + " " + str(bcenter_y) + " CONFIDENCE: " + str(confidence)
        print "END RESULT: " + str(bcenter_x) + " " + str(bcenter_y)

        for j in range(5):
            curr_x = sorted_res[j]["x_coord"]
            curr_y = sorted_res[j]["y_coord"]
            stdX += (curr_x - bcenter_x) * (curr_x - bcenter_x)
            stdY += (curr_y - bcenter_y) * (curr_y - bcenter_y)
        stdX = sqrt(stdX / 5.0)
        stdY = sqrt(stdY / 5.0)

        if (avg_redpin >= 0):
            confidence = 1.0 / (P*math.exp(stdX/stdBaselineX)) + 1.0 / (Q*math.exp(stdY/stdBaselineY)) + 1.0 / (R*math.exp(baselineRedpin/avg_redpin))
        else:
            confidence = 0
        print "CONFIDENCE: " + str(confidence)

    else:
        for key in dist:
            num_readings = len(SignalReading.objects.filter(fingerprint = key, bss__channel__lte=9000, rssie__gte=-90))
            num_aps = max(num_readings, len(fingerprint[f])) 
            nnaps[key] = num_aps - ncaps[key]
            fp = Fingerprint.objects.get(pk=key)
            print str(fp.x_coord) + "," + str(fp.y_coord) + " " + str(dist[key]) + " NCAP: " + str(ncaps[key]) + " NNAP: " + str(nnaps[key])  + " TOTAL: " + str(total_score)

