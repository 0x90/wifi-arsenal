#!/usr/bin/python
import sys, os
import math
import csv
import re
tstamp_coords = {}
fingerprint = {}
counts = {}
orig_counts = {}
means = {}
offset = {}

if len(sys.argv) < 2:
	print "usage: " + sys.argv[0] + " wifi_collect_file.dat "
	sys.exit()
    
wifi_file = sys.argv[1]

with open(wifi_file,"rU") as f:
    reader=csv.reader(f,delimiter='\t')
    for c in reader:
        a = []
        for thing in c:
             thing = re.sub(r'[^\w\-\:]', '', thing)
             a.append(thing)
        c = a
        if len(c) >= 7:
            tstamp, tstampms, tstamp2, bssid, rssi, freq, ssid = c[0:7]
            newssid = ""
            for char in ssid:
                if ord(char) >= 32 and ord(char) < 128:
                    newssid += char
            ssid = newssid
        elif len(c) == 6:
            tstamp, tstampms, tstamp2, bssid, rssi, freq = c
            ssid ="HIDDEN"
        
        if not fingerprint.has_key(tstamp2):
            fingerprint[tstamp2] = []
        bss = {}
        bss["mac_addr"] = bssid
        bss["rssi"] = rssi
        bss["chan"] = freq
        bss["ssid"] = ssid
        bss["hwtstamp"] = tstamp
        bss["tstampms"] = int(int(tstampms)/1000)
        #if int(rssi) > -80:
        #print "tstamp: " + tstamp2
        fingerprint[tstamp2].append(bss)
        
for key in fingerprint:
    for b in fingerprint[key]:
        if not orig_counts.has_key(key):
            orig_counts[key] = {}
            orig_counts[key]['num'] = 0
            orig_counts[key]['hwtstamps'] = {}
        if not orig_counts[key]['hwtstamps'].has_key(b["hwtstamp"]):
            orig_counts[key]['hwtstamps'][b["hwtstamp"]] = 0
            #counts[b["hwtstamp"]] = {}
            #counts[b["hwtstamp"]]['num'] = 0
            #counts[b["hwtstamp"]]['orig'] = key
        orig_counts[key]['hwtstamps'][b["hwtstamp"]] += 1
        orig_counts[key]['num'] += 1

for key in orig_counts:
    #print key + ": " + str(orig_counts[key]['num'])
    orig_counts[key]["mean"]  = orig_counts[key]['num']/len(orig_counts[key]['hwtstamps'])
    #print key + "?: " + str(orig_counts[key]["mean"]) + " " + str(orig_counts[key]['num'])

for key in orig_counts:
    accum = 0
    for reading in fingerprint[key]:
        accum += 1
        if accum >= orig_counts[key]["mean"]:
            orig_counts[key]["offset"] = 1000*(int(reading["hwtstamp"])-int(key)) + int(reading["tstampms"])
            #print "Offset: ", key, " -> ", orig_counts[key]["offset"]
            break
    """
    for key2 in orig_counts[key]["hwtstamps"]:
        if orig_counts[key]["hwtstamps"][key2] + accum >= orig_counts[key]["mean"]:
            #print "for " + key + " choose " + key2
            orig_counts[key]["offset"] = int(key2) - int(key)
            orig_counts[key]["bias_offset"] = 1000*(int(key2) - int(key)) + fingerprint[key]["tstampms"]
            break
        else:
            accum += orig_counts[key]["hwtstamps"][key2]
    """

with open("timeCoords.txt",'r') as f:
    reader=csv.reader(f,delimiter=' ')
    for stamp1, x, y in reader:
        stamp1 = round(float(stamp1),1)
        stamp1 = str(stamp1)
        if not tstamp_coords.has_key(stamp1):
            tstamp_coords[stamp1] = (x,y)

with open("wifi_TimeStampsSync_uniq.txt") as f:
    reader = csv.reader(f,delimiter=' ')
    for unixstamp, sensorstamp in reader:
        sensorstamp=round(float(sensorstamp),1)
	if orig_counts.has_key(unixstamp):
            sensorstamp += round(float(orig_counts[unixstamp]["offset"])/1000.0,1)
            while not tstamp_coords.has_key(str(sensorstamp)):
                print "missing ", sensorstamp
                sensorstamp -= 0.1
            sensorstamp = str(sensorstamp)
            print str(unixstamp) + "\t" + str(tstamp_coords[sensorstamp][0]) + "\t" + str(tstamp_coords[sensorstamp][1]) + "\t" + str(orig_counts[unixstamp]["offset"])
        #if tstamp_coords.has_key(sensorstamp):
        #    print str(unixstamp) + "\t" + str(tstamp_coords[sensorstamp][0]) + "\t" + str(tstamp_coords[sensorstamp][1])
        #else:
        #    print "PROBLEM " + str(sensorstamp)
