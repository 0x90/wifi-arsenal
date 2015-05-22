#!/usr/bin/env python
# Location engine for wpp.
from __future__ import division
from copy import deepcopy
import numpy as np
np_char_array = np.char.array
from numpy import (array, argsort, vstack, searchsorted, reciprocal, average,
        sum as np_sum, abs as np_abs, sort as np_sort, all as np_all, any as np_any)
from lxml.etree import fromstring as xmlparser
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
import logging
wpplog = logging.getLogger('wpp')

from wpp.config import (dbsvrs, DB_ONLINE, KNN, CLUSTERKEYSIZE, KWIN,
        POS_RESP_FULL, POS_RESP_AREA, POS_RESP_PT, GOOG_ERR_LIMIT, DEBUG_ALGO)
from wpp.db import WppDB
from wpp.util.geo import dist_km
from wpp.util.geolocation_api import googleLocation
from wpp.fingerprint import doClusterIncr


def usage():
    from time import strftime
    print """
location.py - Copyleft 2009-%s Yan Xiaotian, yxtbj@139.com.
Location fingerprinting engine using deterministic/probablistic approaches.

usage:
    location <option> <infile>
option:
    -f --fake=<mode id>  :  Fake WLAN scan results in case of bad WLAN coverage.
                            <mode id> same as in WLAN_FAKE of config module.
    -v --verbose         :  Verbose mode.
    -h --help            :  Show this help.
example:
    $location.py -v -f 25  #fake wlan verbose mode.
    $location.py -f 1 -v 
""" % strftime('%Y')


def fixPos(posreq=None, has_google=False, mc=None):
    xmlnodes = xmlparser(posreq).getchildren()
    # Parameters default vals init.
    lat, lon, ee = 39.9055, 116.3914, 5000 
    errinfo = 'AccuTooBad'; errcode = '102'
    # logic control switch init.
    pos_area = pos_pt = False # Default *PosLevel* is Point if not specified.
    # WppDB connection init.
    dbsvr = dbsvrs[DB_ONLINE] 
    wppdb = WppDB(dsn=dbsvr['dsn'], dbtype=dbsvr['dbtype'])
    # lambda func init.
    f = lambda x : [ node.attrib for node in xmlnodes if node.tag == x ] 
    plevel = f('PosLevel')
    # Area location related parameters interpretation & default vals init.
    plevel = plevel[0]['val'] if plevel else 'Point' 
    acode = addr = ''
    if plevel == 'Hybrid': pos_area = pos_pt = True
    elif plevel == 'Area': pos_area = True
    else: 
        pos_pt = True 
        plevel = 'Point' # PosLevel default *Point*.
    if pos_area: # Area location.
        cell = f('CellInfo')
        if cell: 
            laccid = '%s-%s' % (cell[0]['lac'], cell[0]['cid'])
            acode_addr = wppdb.areaLocation(laccid)
            if acode_addr: 
                acode, addr = acode_addr 
                errinfo='OK'; errcode='100'
            lat = lon = ee = ''
    if pos_pt: # Point location, which returns 3d coordinates.
        macs = f('WLANIdentifier'); rsss = f('WLANMatcher'); need_google = False; 
        if macs and rsss:
            macs = macs[0]['val'].split('|') 
            rsss = rsss[0]['val'].split('|')
            INTERSET = min(CLUSTERKEYSIZE, len(macs)) 
            idxs_max = argsort(rsss)[:INTERSET]
            macsrsss = vstack((macs, rsss))[:,idxs_max]
            wlanloc = fixPosWLAN(INTERSET, macsrsss, wppdb, DEBUG_ALGO)
            if not wlanloc: 
                need_google = True
        else: wlanloc = []
        if not wlanloc: 
            if not pos_area: cell = f('CellInfo')
            if cell:
                if not pos_area: 
                    laccid = '%s-%s' % (cell[0]['lac'], cell[0]['cid'])
                celloc = wppdb.laccidLocation(laccid)
                if not celloc: 
                    need_google = True 
                    wpplog.error('Cell location FAILED!')
                elif celloc[2] > GOOG_ERR_LIMIT: 
                    need_google = False  # googleLocation err too big for wlanloc.
                else: pass
            else: celloc = []
        loc = wlanloc or celloc
        if loc: 
            lat, lon, ee = loc
            errinfo = 'OK'; errcode = '100'
        # TODO: make googleLocation async job when wlanloc fails & celloc succeeds.
        # Try Google location, when wifi location failed && wifi info exists.
        if need_google and has_google: 
            loc_google = googleLocation(macs=macs, rsss=rsss, cellinfo=cell[0], mc=mc) 
            if loc_google:
                lat1, lon1, h, ee_goog = loc_google 
                if not loc:
                    lat, lon, ee = lat1, lon1, ee_goog
                    errinfo = 'OK'; errcode = '100'
                # wifi location import. TODO: make google loc import job async when it's *succeeded*.
                if macs and ee_goog <= GOOG_ERR_LIMIT:
                    t = f('Time')
                    t = t[0]['val'] if t else ''
                    fp = '1000, 1000101, %s%s%s, %s, %s, %s, %s' % \
                            (t,','*9,lat1, lon1, h, '|'.join(macs), '|'.join(rsss))
                    n = doClusterIncr(fd_csv=StringIO(fp), wppdb=wppdb, verb=False)
                    if n['n_newfps'] == 1: 
                        wpplog.info('Added 1 WLAN FP from Google')
                    else: 
                        wpplog.error('Failed to add FP from Google!')
                # Cell location import.
                if cell and not celloc:
                    if ee_goog <= GOOG_ERR_LIMIT: 
                        loc_google[-1] = 500
                    wppdb.addCellLocation(laccid=laccid, loc=loc_google)
                    wpplog.info('Added 1 Cell FP from Google')
            else: wpplog.error('Google location FAILED!')
    wppdb.close()
    if plevel == 'Hybrid': posresp = POS_RESP_FULL % (errcode, errinfo, lat, lon, ee, plevel, acode, addr)
    elif plevel == 'Area': posresp = POS_RESP_AREA % (errcode, errinfo, plevel, acode, addr)
    else: posresp = POS_RESP_PT % (errcode, errinfo, lat, lon, ee, plevel)

    return posresp


def fixPosWLAN(len_wlan=None, wlan=None, wppdb=None, verb=False):
    """
    Returns the online fixed user location in lat/lon format.
    
    Parameters
    ----------
    len_wlan: int, mandatory
        Number of online visible WLAN APs.
    wlan: np.array, string list, mandatory
        Array of MAC/RSS for online visible APs.
        e.g. [['00:15:70:9E:91:60' '00:15:70:9E:91:61' '00:15:70:9E:91:62' '00:15:70:9E:6C:6C']
              ['-55' '-56' '-57' '-68']]. 
    verb: verbose mode option, default: False
        More debugging info if enabled(True).
    
    Returns
    -------
    posfix: np.array, float
        Final fixed location(lat, lon).
        e.g. [ 39.922942  116.472673 ]
    """
    interpart_offline = False; interpart_online = False

    # db query result: [ maxNI, keys:[ [keyaps:[], keycfps:(())], ... ] ].
    # maxNI=0 if no cluster found.
    maxNI,keys = wppdb.getBestClusters(macs=wlan[0])
    #maxNI,keys = [2, [
    #    [['00:21:91:1D:C0:D4', '00:19:E0:E1:76:A4', '00:25:86:4D:B4:C4'], 
    #        [[5634, 5634, 39.898019, 116.367113, '-83|-85|-89']] ],
    #    [['00:21:91:1D:C0:D4', '00:25:86:4D:B4:C4'],
    #        [[6161, 6161, 39.898307, 116.367233, '-90|-90']] ] ]]
    if maxNI == 0: # no intersection found
        wpplog.error('NO cluster found! Fingerprinting TERMINATED!')
        return []
    elif maxNI < CLUSTERKEYSIZE:
        # size of intersection set < offline key AP set size:4, 
        # offline keymacs/keyrsss (not online maxmacs/maxrsss) need to be cut down.
        interpart_offline = True
        if maxNI < len_wlan: #TODO: TBE.
            # size of intersection set < online AP set size(len_wlan) < CLUSTERKEYSIZE,
            # not only keymacs/keyrsss, but also maxmacs/maxrsss need to be cut down.
            interpart_online = True
        if verb: wpplog.debug('Partly[%d] matched cluster(s) found:' % maxNI)
    else: 
        if verb: wpplog.debug('Full matched cluster(s) found:')
    if verb: wpplog.debug('keys:\n%s' % keys)

    # Evaluation|sort of similarity between online FP & radio map FP.
    # fps_cand: [ min_spid1:[cid,spid,lat,lon,rsss], min_spid2, ... ]
    # keys: ID and key APs of matched cluster(s) with max intersect APs.
    all_pos_lenrss = []
    fps_cand = []; sums_cand = []
    for keyaps,keycfps in keys:
        if verb: wpplog.debug('keyaps:\n%s\nkeycfps:\n%s' % (keyaps, keycfps))
        # Fast fix when the ONLY 1 selected cid has ONLY 1 fp in 'cfps'.
        if len(keys)==1 and len(keycfps)==1:
            fps_cand = [ list(keycfps[0]) ]
            break
        pos_lenrss = (array(keycfps)[:,1:3].astype(float)).tolist()
        keyrsss = np_char_array(keycfps)[:,4].split('|') #4: column order in cfps.tbl
        keyrsss = array([ [float(rss) for rss in spid] for spid in keyrsss ])
        for idx,pos in enumerate(pos_lenrss):
            pos_lenrss[idx].append(len(keyrsss[idx]))
        all_pos_lenrss.extend(pos_lenrss)
        # Rearrange key MACs/RSSs in 'keyrsss' according to intersection set 'keyaps'.
        if interpart_offline:
            if interpart_online:
                wl = deepcopy(wlan) # mmacs->wl[0]; mrsss->wl[1]
                idxs_inters = [ idx for idx,mac in enumerate(wlan[0]) if mac in keyaps ]
                wl = wl[:,idxs_inters]
            else: wl = wlan
        else: wl = wlan
        idxs_taken = [ keyaps.index(x) for x in wl[0] ]
        keyrsss = keyrsss.take(idxs_taken, axis=1)
        mrsss = wl[1].astype(int)
        # Euclidean dist solving and sorting.
        sum_rss = np_sum( (mrsss-keyrsss)**2, axis=1 )
        fps_cand.extend( keycfps )
        sums_cand.extend( sum_rss )
        if verb: wpplog.debug('sum_rss:\n%s' % sum_rss)

    # Location estimation.
    if len(fps_cand) > 1:
        # KNN
        # lst_set_sums_cand: list format for set of sums_cand.
        # bound_dist: distance boundary for K-min distances.
        lst_set_sums_cand =  array(list(set(sums_cand)))
        idx_bound_dist = argsort(lst_set_sums_cand)[:KNN][-1]
        bound_dist = lst_set_sums_cand[idx_bound_dist]
        idx_sums_sort = argsort(sums_cand)

        sums_cand = array(sums_cand)
        fps_cand = array(fps_cand)

        sums_cand_sort = sums_cand[idx_sums_sort]
        idx_bound_fp = searchsorted(sums_cand_sort, bound_dist, 'right')
        idx_sums_sort_bound = idx_sums_sort[:idx_bound_fp]
        #idxs_kmin = argsort(min_sums)[:KNN]
        sorted_sums = sums_cand[idx_sums_sort_bound]
        sorted_fps = fps_cand[idx_sums_sort_bound]
        if verb: wpplog.debug('k-dists:\n%s\nk-locations:\n%s' % (sorted_sums, sorted_fps))
        # DKNN
        if sorted_sums[0]: 
            boundry = sorted_sums[0]*KWIN
        else: 
            if sorted_sums[1]:
                boundry = KWIN
                # What the hell are the following two lines doing here!
                #idx_zero_bound = searchsorted(sorted_sums, 0, side='right')
                #sorted_sums[:idx_zero_bound] = boundry / (idx_zero_bound + .5)
            else: boundry = 0
        idx_dkmin = searchsorted(sorted_sums, boundry, side='right')
        dknn_sums = sorted_sums[:idx_dkmin].tolist()
        dknn_fps = sorted_fps[:idx_dkmin]
        if verb: wpplog.debug('dk-dists: \n%s\ndk-locations: \n%s' % (dknn_sums, dknn_fps))
        # Weighted_AVG_DKNN.
        num_dknn_fps = len(dknn_fps)
        if  num_dknn_fps > 1:
            coors = dknn_fps[:,1:3].astype(float)
            num_keyaps = array([ rsss.count('|')+1 for rsss in dknn_fps[:,-2] ])
            # ww: weights of dknn weights.
            ww = np_abs(num_keyaps - len_wlan).tolist()
            #wpplog.debug(ww)
            if not np_all(ww):
                if np_any(ww):
                    ww_sort = np_sort(ww)
                    #wpplog.debug('ww_sort: %s' % ww_sort)
                    idx_dknn_sums_sort = searchsorted(ww_sort, 0, 'right')
                    #wpplog.debug('idx_dknn_sums_sort: %s' % idx_dknn_sums_sort)
                    ww_2ndbig = ww_sort[idx_dknn_sums_sort] 
                    w_zero = ww_2ndbig / (len(ww)*ww_2ndbig)
                else: w_zero = 1
                #for idx,sum in enumerate(ww):
                #    if not sum: ww[idx] = w_zero
                ww = [ w if w else w_zero for w in ww ]
            ws = array(ww) + dknn_sums
            weights = reciprocal(ws)
            if verb: wpplog.debug('coors:%s, weights:%s' % (coors, weights))
            posfix = average(coors, axis=0, weights=weights)
        else: posfix = array(dknn_fps[0][1:3]).astype(float)
        # ErrRange Estimation (more than 1 relevant clusters).
        idxs_clusters = idx_sums_sort_bound[:idx_dkmin]
        if len(idxs_clusters) == 1: 
            if maxNI == 1: poserr = 200
            else: poserr = 100
        else: 
            if verb: wpplog.debug('idxs_clusters: %s\nall_pos_lenrss: %s' % (idxs_clusters, all_pos_lenrss))
            #allposs_dknn = vstack(array(all_pos_lenrss, object)[idxs_clusters])
            allposs_dknn = array(all_pos_lenrss, object)[idxs_clusters]
            if verb: wpplog.debug('allposs_dknn: %s' % allposs_dknn)
            poserr = max( average([ dist_km(posfix[1], posfix[0], p[1], p[0])*1000 
                for p in allposs_dknn ]), 100 )
    else: 
        fps_cand = fps_cand[0][:-2]
        if verb: wpplog.debug('location:\n%s' % fps_cand)
        posfix = array(fps_cand[1:3]).astype(float)
        # ErrRange Estimation (only 1 relevant clusters).
        N_fp = len(keycfps)
        if N_fp == 1: 
            if maxNI == 1: poserr = 200
            else: poserr = 150
        else:
            if verb: 
                wpplog.debug('all_pos_lenrss: %s' % all_pos_lenrss)
                wpplog.debug('posfix: %s' % posfix)
            poserr = max( np_sum([ dist_km(posfix[1], posfix[0], p[1], p[0])*1000 
                for p in all_pos_lenrss ]) / (N_fp-1), 100 )
    ret = posfix.tolist()
    ret.append(poserr)

    return ret


def getWLAN(fake=0):
    """
    Returns the number and corresponding MAC/RSS info of online visible APs.
    
    Parameters
    ----------
    fake: fake WLAN scan option, int, default: 0
        Use old WLAN scanned data stored in WLAN_FAKE if valid value is taken.
    
    Returns
    -------
    (len_scanAP, scannedwlan): tuple, (int, array)
        Number and corresponding MAC/RSS info of online visible APs in tuple.
    """
    from wpp.config import WLAN_FAKE
    from errno import EPERM
    if fake == 0:   # True WLAN scan.
        from wpp.util.wlan import scanWLAN_OS#, scanWLAN_RE
        #scannedwlan = scanWLAN_RE()
        scannedwlan = scanWLAN_OS()
        if scannedwlan == EPERM: # fcntl.ioctl() not permitted.
            print 'For more information, please use \'-h/--help\'.'
            sys.exit(99)
    else:           # CMRI or Home.
        #addrid = fake
        try: scannedwlan = WLAN_FAKE[fake]
        except KeyError, e:
            print "\nError(%s): Illegal WLAN fake ID: '%d'!" % (e, fake) 
            print "Supported IDs: %s" % WLAN_FAKE.keys()
            sys.exit(99)
    # Address book init.
    #addr = addr_book[addrid]

    len_scanAP = len(scannedwlan)
    if len(scannedwlan) == 0: sys.exit(0)   

    INTERSET = min(CLUSTERKEYSIZE, len_scanAP)
    # All integers in rss field returned by scanWLAN_OS() 
    # are implicitly converted to strings during array(scannedwlan).
    scannedwlan = array(scannedwlan).T
    idxs_max = argsort(scannedwlan[1])[:INTERSET]
    # TBE: Necessity of different list comprehension for maxmacs and maxrsss.
    scannedwlan = scannedwlan[:,idxs_max]
    wpplog.debug('Selected APs(%d): %s' % (len_scanAP, scannedwlan))

    return (INTERSET, scannedwlan)


def main():
    import getopt
    try: opts, args = getopt.getopt(sys.argv[1:], 
            # NO backward compatibility for file handling, so the relevant 
            # methods(os,pprint)/parameters(addr_book,XXXPATH) 
            # imported from standard or 3rd-party modules can be avoided.
            "f:hv",
            ["fake","help","verbose"])
    except getopt.GetoptError:
        print 'Error: getopt!\n'
        usage(); sys.exit(99)

    # Program terminated when NO argument followed!
    #if not opts: usage(); sys.exit(0)

    # vars init.
    verbose = False; wlanfake = 0

    for o,a in opts:
        if o in ("-f", "--fake"):
            if a.isdigit(): 
                wlanfake = int(a)
                if wlanfake >= 0: continue
                else: pass
            else: pass
            print '\nIllegal fake WLAN scan ID: %s!' % a
            usage(); sys.exit(99)
        elif o in ("-h", "--help"):
            usage(); sys.exit(0)
        elif o in ("-v", "--verbose"):
            verbose = True
        else:
            print 'Parameter NOT supported: %s' % o
            usage(); sys.exit(99)


    # Get WLAN scanning results.
    len_visAPs, wifis = getWLAN(wlanfake)

    # Fix current position.
    dbsvr = dbsvrs[DB_ONLINE] 
    wppdb = WppDB(dsn=dbsvr['dsn'], dbtype=dbsvr['dbtype'])
    posresult = fixPosWLAN(len_visAPs, wifis, wppdb, verbose)
    if not posresult: sys.exit(99)
    wpplog.debug('final posfix/poserr: \n%s' % posresult)


if __name__ == "__main__":
    import sys
    from wpp.config import wpplog, Formatter, loghandler
    logfmt = Formatter('<%(asctime)s,%(levelname)s ==> %(message)s')
    loghandler.setFormatter(logfmt)
    wpplog.addHandler(loghandler)
    wpplog.setLevel(logging.DEBUG)
    try:
        import psyco
        #psyco.bind(scanWLAN_OS)
        psyco.bind(getWLAN)
        psyco.bind(fixPosWLAN)
        #psyco.bind(fixPos)
        #psyco.full()
        #psyco.log()
        #psyco.profile(0.3)
    except ImportError:
        pass
    main()
