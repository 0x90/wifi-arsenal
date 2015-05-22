#!/usr/bin/python
import sys, os
import math
import time
import re
from math import sqrt, exp
from django.core.cache import cache
#sys.path.append('/Users/stephen/Documents/wifi')
#os.environ['DJANGO_SETTINGS_MODULE'] = 'wifi.settings'
#from django.db import models
from wifi.models import *


algtype = "redpin"

SIGNAL_CONTRIBUTION = 1
SIGNAL_PENALTY_THRESHOLD = 10
SIGNAL_GRAPH_LEVELING = 0.2

# Parameters for confidence value calculation
stdBaselineX = 2.54
stdBaselineY = 2.54
baselineRedpin = 10.0
P = 6.0
Q = 6.0
R = 3.0/2.0


def redpin_score(rssi1, rssi2):
    base = rssi1
    diff = abs(rssi1 - rssi2)
    x = diff / abs(base)
    y = 0
    if (x > 0.0):
        y = 1 / x
        t = SIGNAL_PENALTY_THRESHOLD / base
        y -= 1 / t
        y = y * SIGNAL_GRAPH_LEVELING
        return y
    return SIGNAL_CONTRIBUTION



def measure(reading):
    #print len(reading)
    bss_reading = {}
    dist = {}
    ncaps = {}
    nnaps = {}
    scores = {}
    ncap_list = {}
    mac_regex= re.compile('^\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}$')
    cluster_id = 1
    freq_filter = 9000
    cutoff_dB = -65
    if reading.has_key("cluster_id"):
        cluster_id = reading["cluster_id"]
    if reading.has_key("freq_filter"):
        freq_filter = reading["freq_filter"]
    if reading.has_key("cutoff_dB"):
        cutoff_dB = reading["cutoff_dB"]
        
    for key in reading:
        if not mac_regex.match(key):
            continue
        
        a = key.lower()
        a = a.replace(":","-")
        #if int(reading[key]) > cutoff_dB:
        last_bytes = a.split("-")[4] + "-" + a.split("-")[5]
        bss_reading[last_bytes] = reading[key]
    initial_comp = time.time()  
    total_time = 0.0
       
    for key in bss_reading:
        bss_time = time.time()
        bss_set = cache.get("bssset_" + key)
        if bss_set is None:
            #print "NO CACHE!!"
            bss_set = list(Bss.objects.filter(mac_addr__iendswith=key, cluster=cluster_id))
            cache.set("bssset_" + key, bss_set)
        #print bss_set.query
        for b in bss_set:
            bss_time = time.time()
            signals = cache.get("sreading_" + str(b.id))
            if signals is None:
                signals = list(SignalReading.objects.filter(bss=b, bss__channel__lte=freq_filter, rssi__gte=cutoff_dB))
                cache.set("sreading_" + str(b.id), signals)
            #print signals.query
            #print len(signals)
            total_time += time.time()-bss_time
            #print "BSS GET TIME: ", time.time()-bss_time
            for s in signals:
                fpid = s.fingerprint_id
                if not dist.has_key(fpid):
                    dist[fpid] = 0.0
                if not scores.has_key(fpid):
                    scores[fpid] = 0.0
                if not ncaps.has_key(fpid):
                    ncaps[fpid] = 0
                if not ncap_list.has_key(fpid):
                    ncap_list[fpid] = ""
                ncaps[fpid] += 1
                #ncap_list[f.pk] += s.bss.mac_addr + ": " + s.bss.ssid + ","
                curr_score = redpin_score(float(bss_reading[key]), float(s.rssi))
                scores[fpid] += curr_score
    
    

    print "Initial computation ", time.time() - initial_comp
    
    results = []
    sorted_res = {}
    start_time = time.time()

    for key in scores:
            num_readings = len(SignalReading.objects.filter(fingerprint = key, bss__channel__lte=freq_filter, rssi__gte=cutoff_dB))
            num_aps = max(num_readings, len(bss_reading))
            nnaps[key] = num_aps - ncaps[key]
            fp = Fingerprint.objects.get(pk=key)
            total_score = 0.2*scores[key] + 1.0*ncaps[key] - 0.4*nnaps[key]
            tmpres = {}
            tmpres["x_coord"] = fp.x_coord
            tmpres["y_coord"] = fp.y_coord
            tmpres["bias_offset"] = fp.bias_offset
            tmpres["dist"] = scores[key]
            tmpres["ncaps"] = ncaps[key]
            tmpres["nnaps"] = nnaps[key]
            tmpres["redpin_score"] = total_score
            results.append(tmpres)
        
    print "Computation time: ", time.time()-start_time


    sorted_res = sorted(results, key=lambda k: k["redpin_score"], reverse=True)

    sum_of_redpin = 0        
    stdX = 0
    stdY = 0
    i = 0
    bcenter_x = 0
    bcenter_y = 0
    bcenter_pts = 5
    avg_bias_offset = 0
    for res in sorted_res:
        if i < bcenter_pts:
            sum_of_redpin += res["redpin_score"]
            bcenter_x += res["x_coord"]
            bcenter_y += res["y_coord"]
            avg_bias_offset += res["bias_offset"]
        #print str(res["x_coord"]) + "," + str(res["y_coord"]) + "," + str(res["dist"]) + "," + str(res["ncaps"]) + "," + str(res["nnaps"]) + "," + str(res["redpin_score"])
        i += 1
        
    bcenter_x /= float(bcenter_pts)
    bcenter_y /= float(bcenter_pts)
    avg_bias_offset /= bcenter_pts
    avg_redpin = sum_of_redpin / float(bcenter_pts) 
    #print "END RESULT: " + str(bcenter_x) + " " + str(bcenter_y)


    if (len(sorted_res) < 1):
        print "No matches found!"
    else:
        limit = min(bcenter_pts, len(sorted_res))
        for j in range(limit):
            curr_x = sorted_res[j]["x_coord"]
            curr_y = sorted_res[j]["y_coord"]
            stdX += (curr_x - bcenter_x) * (curr_x - bcenter_x)
            stdY += (curr_y - bcenter_y) * (curr_y - bcenter_y)
        stdX = sqrt(stdX / limit)
        stdY = sqrt(stdY / limit)

        if (avg_redpin >= 0):
            confidence = 1.0 / (P*exp(stdX/stdBaselineX)) + 1.0 / (Q*exp(stdY/stdBaselineY)) + 1.0 / (R*exp(baselineRedpin/avg_redpin))
        else:
            confidence = 0
        #print "CONFIDENCE: " + str(confidence) + " BIAS: " + str(avg_bias_offset)
        print bcenter_x, " ", bcenter_y, " ", confidence
        #print "freq filter: ", freq_filter
        return (bcenter_x, bcenter_y, confidence, avg_bias_offset)

