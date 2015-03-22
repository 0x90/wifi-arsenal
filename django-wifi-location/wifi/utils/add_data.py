#!/usr/bin/python
import sys, os
import csv
import re
sys.path.append('/Users/stephen/Documents/wifi')
sys.path.append('/home/nm/work/wifi')
sys.path.append('/home/django/wifi')
os.environ['DJANGO_SETTINGS_MODULE'] = 'wifi.settings'
from django.db import models
from wifi.models import *


valid = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_ ')
def test(s):
    return set(s).issubset(valid)

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
      
coord_file = ""
x_coords = {}
y_coords = {}
bias = {}


if len(sys.argv) < 4:
	print "usage: " + sys.argv[0] + " input_file coords_file cluster_name"
	sys.exit()
coord_file = sys.argv[2]

max_timestamp = ""
if len(sys.argv) >= 5:
    max_timestamp = sys.argv[4]

with open(coord_file, 'r') as f:
    reader = csv.reader(f, delimiter='\t')
    for line in reader:
        if len(line) == 3:
            tstamp, x_coord, y_coord = line
        else:
            tstamp, x_coord, y_coord, bias_offset = line
        x_coords[tstamp] = x_coord
        y_coords[tstamp] = y_coord
        bias[tstamp] = bias_offset
        #print tstamp, x_coord, y_coord



print "Adding data from "  + sys.argv[1]
fingerprint = {}
with open(sys.argv[1], 'rU') as f:
    reader = csv.reader(f, delimiter='\t')
    for c in reader:
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
        else:
            continue
        if tstamp2 == max_timestamp:
            break
        ssid = re.sub(r'[^A-Za-z0-9\-]+', '', ssid)
        if not fingerprint.has_key(tstamp2):
            fingerprint[tstamp2] = []
        bss = {}
        bss["mac_addr"] = bssid
        bss["rssi"] = rssi
        bss["chan"] = freq
        bss["ssid"] = ssid
        #if int(rssi) > -80:
        fingerprint[tstamp2].append(bss)



cl = Cluster()
cl.cluster_name=sys.argv[3]
cl.save()


x = 0
y = 0


for tstamp in sorted(fingerprint.iterkeys()):
    f = Fingerprint()
    if coord_file:
        f.x_coord = x_coords[tstamp]
        f.y_coord = y_coords[tstamp]
        f.bias_offset = bias[tstamp]
    else:
        f.x_coord = x
        f.y_coord = y
    f.save()
    x += 1
    for bss in fingerprint[tstamp]:
        b = Bss.objects.filter(mac_addr = bss["mac_addr"])
        if not b:
            b = Bss()
            bss["ssid"] = bss["ssid"][0:32]
            b.mac_addr = bss["mac_addr"]
            b.channel = bss["chan"]
            b.ssid = bss["ssid"]
            b.save()
            bc = BssToCluster()
            bc.bss = b
            bc.cluster = cl
            bc.save()
        else:
            b = b[0]
            
        try:
	    cf = ClusterToFingerprint.objects.get(cluster=cl,fingerprint=f)
	except Exception as e1:    
            cf = ClusterToFingerprint()
            cf.cluster = cl
            cf.fingerprint = f
            cf.save()
        
        sr = SignalReading()
        sr.fingerprint = f
        sr.bss = b
        sr.rssi = bss["rssi"]
        sr.save()
print "Added fingerprints to database"
