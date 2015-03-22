## Loop scan for wireless x-driving
import wlantools as wl
import time as ti
import sysinfo as si
import location as loc
import positioning as pos
import audio as aud
import os
import sys


NUMLOOP=5000

imei = si.imei()
uagent = si.sw_version().split()[-1]

date = ti.strftime('%Y%m%d')

log_dir = "e:\\data\\wlan"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
logfile = os.path.join(log_dir, 'fpp_RawData_CMRI_'+date+'.csv')
fout = open(logfile, 'a')

media = "e:\\videos\\noti.mid"
try:
    snd = aud.Sound.open(media) 
    #print 'Sound ready!'
except:
    print 'Oops! NOT available: %s!' % media

print
print 'IMEI:%s\nUserAgent:%s' % (imei, uagent)
mod = pos.default_module() # A-GPS as first time fixer
pos.select_module(mod) 
modinfo = pos.module_info(mod)
print '%s:%s,QoD:%s' % (modinfo['name'],modinfo['id'],modinfo['status']['data_quality'])
try:
    # set_requestors() must follows select_module()
    pos.set_requestors([{"type":"service","format":"application","data":"test_app"}])
    gpsdict = pos.position(satellites=True)
except:
    print 'Oops! GPS failed!'
    pos.stop_position()
    sys.exit(1)


mod -= 2
pos.select_module(mod)  # Built-in GPS
modinfo = pos.module_info(mod)
pos.set_requestors([{"type":"service","format":"application","data":"test_app"}])


for iscan in range(NUMLOOP):
    print '%sScan %d%s' % ('-'*12, iscan+1, '-'*12)

    cellok = 1 # Cell info OK.
    celloc = loc.gsm_location()
    if (not isinstance(celloc, tuple)) or (not len(celloc) == 4):
        print 'Oops! GSM location FAILED!'
        cellok = 0
    else:
        celloc = [ str(x) for x in celloc ]
        cellrss = str(si.signal_dbm() - 127)
        print 'CellInfo:%s,%s,%s,%s,%s' % (celloc[0],celloc[1],celloc[2],celloc[3],cellrss)

    gpsok = 1 # GPS data OK.
    try:
        gpsdict = pos.position(satellites=True)
    except:
        print 'Oops! GPS failed!'
        gpsok = 0
    if gpsok:
        gpspos = gpsdict['position']    # position
        gpssat = gpsdict['satellites']  # satellites
        #gpscrs = gpsdict['course']      # course
        sat_used = gpssat['used_satellites']
        sat_view = gpssat['satellites']
        gps = [ str(gpspos[x]) for x in ('latitude','longitude','altitude') ]
        print '%s:%s,sat:%s/%s' % (modinfo['name'],modinfo['id'],sat_used,sat_view)
        print 'Coord:%s,%s,%s' % (gps[0][:8], gps[1][:9], gps[2][:4])

    wlanok = 1 # wlan data OK.
    wlans = wl.scan(False) # wl.scan(1) not steady enough according to nokia forum
    if wlans:
        macs = []; rsss = []
        num_wlan=len(wlans)
        #print 'APs found: %d' % num_wlan
        for iap in range(num_wlan):
            ap = wlans[iap]
            mac = ap['BSSID']
            rss = ap['RxLevel']
            print '%d>%s,%s...%s,%s' % (iap+1, ap['SSID'], mac[:2], mac[-5:], rss)
            macs.append(mac)
            rsss.append(str(rss))
    else: wlanok = 0

    timestamp = ti.strftime('%Y%m%d-%H%M%S')

    # logdata: compatible with fpp-wpp rawdata spec, which defines the sampling data format: 
    # IMEI,IMSI,UserAgent,MCC,MNC,LAC,CI,rss,lat,lon,h,wlanmacs,wlanrsss,Time
    systat = cellok + wlanok + gpsok
    if systat == 2 or systat == 3: 
        if systat == 2:
            if not wlanok: 
                macs = rsss = ['']
            elif not cellok: 
                celloc = ['','','','']
                cellrss = ''
            else: 
                gps = ['','','']
        else: pass
    else:
        continue
    logdata = [imei,'',uagent]+celloc+[cellrss]+gps+['|'.join(macs)]+['|'.join(rsss),timestamp]
    logstr = ','.join(logdata)

    try: # Succeed in collecting one record.
        snd.play()
    except:
        print 'Oops! play sound ERROR: %s!' % media
    fout.write(logstr + "\r\n")

    ti.sleep(4)

pos.stop_position()
fout.close()
