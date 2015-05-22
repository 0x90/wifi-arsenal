#!/usr/bin/env python
# Fingerprint data model for wpp offline processing(online location ONLY deals with db data).
from __future__ import division
import os, sys
import csv
import numpy as np
from progressbar import ProgressBar, Percentage, Bar, RotatingMarker

from wpp.config import CSV_CFG_RFP, FP_FIELD_NAMES, CLUSTERKEYSIZE


def doClusterIncr(fd_csv=None, wppdb=None, verb=True):
    """
    Parameters
    ----------
    fd_csv: file descriptor of rawdata in csv format.
    wppdb: object of wpp.db.WppDB.
    verb: show detailed incr-cluster progressbar if TRUE.
    
    Returns
    -------
    n_inserts : { 'n_newcids':0, 'n_newfps':0 },
            n_newcids: New clusters added,
            n_newfps: New FPs added.
    """
    csvdat = csv.reader(fd_csv)
    try:
        rawrmp = np.array([ fp for fp in csvdat ])
        num_rows, num_cols = np.shape(rawrmp)
    except csv.Error, e:
        sys.exit('\nERROR: line %d: %s!\n' % (csvdat.line_num, e))
    # CSV format judgement.
    print 'Parsing FPs for Incr clustering: [%s]' % num_rows
    try:
        csv_cols = CSV_CFG_RFP[num_cols]
    except KeyError:
        sys.exit('\nERROR: Unsupported csv format!\n')
    try:
        col_lat = csv_cols['lat']
        col_lon = csv_cols['lon']
    except KeyError:
        col_iac = csv_cols['iac']
        col_bid = csv_cols['bid']
        # Modify wppdb.tbl_field to support indoor wpp db schema.
        wppdb.tbl_field['wpp_cfps'] = ('clusterid', 'iac', 'h', 'building_id', 'time', 'rsss')
    col_macs = csv_cols['macs']
    col_rsss = csv_cols['rsss']
    col_h    = csv_cols['h']
    col_time = csv_cols['time']
    #print 'CSV format: %d fields' % num_cols
        
    # Rearrange & truncate(consists of CLUSTERKEYSIZE ones) MACs & RSSs in rawrmp by descending order.
    # topaps: array of splited aps strings for all fingerprints.
    sys.stdout.write('Selecting MACs for clustering ... ')
    topaps = np.char.array(rawrmp[:,col_macs]).replace(' ','').split('|')
    toprss = np.char.array(rawrmp[:,col_rsss]).replace(' ','').split('|')
    joinaps = []
    for i in xrange(len(topaps)):
        macs = np.array(topaps[i])
        rsss = np.array(toprss[i])
        idxs_max = np.argsort(rsss)[:CLUSTERKEYSIZE]
        topaps[i] = macs[idxs_max]
        joinaps.append('|'.join(topaps[i]))
        toprss[i] = '|'.join(rsss[idxs_max])
    rawrmp[:,col_macs] = np.array(joinaps)
    rawrmp[:,col_rsss] = np.array(toprss)
    print 'Done'

    # Clustering heuristics.
    fp_field_names = FP_FIELD_NAMES['outdoor']  if 'lat' in csv_cols else FP_FIELD_NAMES['indoor'] 
    idxs_fp = [ csv_cols[col] for col in fp_field_names ]
    idx_time = fp_field_names.index('time')
    idx_rsss = fp_field_names.index('rsss')
    n_inserts = { 'n_newcids':0, 'n_newfps':0 }
    if verb:
        widgets = ['Incr-Clustering: ',Percentage(),' ',Bar(marker=RotatingMarker())]
        pbar = ProgressBar(widgets=widgets, maxval=num_rows*10).start()
    for idx, wlanmacs in enumerate(topaps):
        # Drop FPs with no wlan info.
        if not wlanmacs[0].strip() and len(wlanmacs) == 1:
            continue
        fp = rawrmp[ idx, idxs_fp ]
        found_cluster, result = search_cluster(macs=wlanmacs, fp=fp, wppdb=wppdb, idx_rsss=idx_rsss)
        fp = result['fp']
        # Strip time & rsss field.
        fp[idx_time] = fp[idx_time].replace(' ','')
        fp[idx_rsss] = fp[idx_rsss].replace(' ','')
        if not found_cluster:
            # Insert into cidaps/cfps with a new clusterid.
            new_cid = wppdb.addCluster(result['fp_macs'])
            wppdb.addFps(cid=new_cid, fps=[fp])
            n_inserts['n_newcids'] += 1
        else:
            # Insert fingerprints into the found cluster.
            # Re-arrange FP rsss according to the ascending seq order of |clusteridaps| keyaps.
            fp_rsss = fp[idx_rsss].split('|')
            fp_macs = result['fp_macs'].tolist()
            cluster_macs = result['cluster_macs']
            fp[idx_rsss] = '|'.join([ fp_rsss[fp_macs.index(m)] for m in cluster_macs ])
            wppdb.addFps(cid=result['cid'], fps=[fp])
        n_inserts['n_newfps'] += 1
        if verb: pbar.update(10*idx+1)
    if verb: pbar.finish()
    return n_inserts


def search_cluster(macs=None, fp=None, wppdb=None, **kw):
    """
    1) Search for best matched cluster, or create a new one.
    2) Filtering MACs thru decorators.
    """
    found = False
    result = {'fp': fp, 'fp_macs': macs}
    # Filter out the duplicated macs & rsss.
    if len(macs) != len(set(macs)):
        idx_rsss = kw['idx_rsss']
        new_wifi = np.array([ ( x, fp[idx_rsss].split('|')[list(macs).index(x)]) for x in set(macs) ])
        idx_sortbyrss = np.argsort(new_wifi[:,1])
        new_wifi = new_wifi[idx_sortbyrss, :]
        result['fp'][idx_rsss] = '|'.join(new_wifi[:,1])
        result['fp_macs'] = macs = new_wifi[:,0]
    #     cidcntseq: all query results from db: cid,count(cid),max(seq).
    # cidcntseq_max: query results with max count(cid).
    cidcntseq = wppdb.getCIDcntMaxSeq(macs=macs)
    if cidcntseq:
        # find out the most queried cluster /w the same AP count:
        # cid count = max seq
        cidcntseq = np.array(cidcntseq)
        cidcnt = cidcntseq[:,1]
        #print cidcntseq
        idxs_sortdesc = np.argsort(cidcnt).tolist()
        idxs_sortdesc.reverse()
        #print idxs_sortdesc
        cnt_max = cidcnt.tolist().count(cidcnt[idxs_sortdesc[0]])
        cidcntseq_max = cidcntseq[idxs_sortdesc[:cnt_max],:]
        #print cidcntseq_max
        idx_belong = cidcntseq_max[:,1].__eq__(cidcntseq_max[:,2])
        #print idx_belong
        if sum(idx_belong):
            # cids_belong: [clusterid, number of keyaps]
            cids_belong = cidcntseq_max[idx_belong,[0,2]]
            result['cid'] = cids_belong[0]
            if cids_belong[1] == len(macs):
                found = True
                result['cluster_macs'] = wppdb.getClusterMACs(cid=result['cid'])
    return (found, result)


def genFPs(rawfile):
    """
    Generating (unclustered) fingerprint for certain sampling point(specified by 
        raw file content) from GPS/WLAN raw scanned data.

    Parameters
    ----------
    rawfile : GPS/WLAN raw scanned data file (spid, time, lat, lon, macs, rsss).

    Returns
    -------
    fingerprint = [ spid, lat_mean, lon_mean, mac_interset_rmp, rss_interset_rmp, time ]
    """
    rawin = csv.reader( open(rawfile,'r') )
    latlist=[]; lonlist=[]; mac_raw=[]; rss_raw=[]
    maclist=[]; mac_interset=[]
    try:
        for rawdata in rawin:
            spid = int(rawdata[0])
            time = int(rawdata[1])
            latlist.append(string.atof(rawdata[2]))
            lonlist.append(string.atof(rawdata[3]))
            mac_raw.append(rawdata[4])
            rss_raw.append(rawdata[5])
    except csv.Error, e:
        sys.exit('\nERROR: %s, line %d: %s!\n' % (rawfile, rawin.line_num, e))

    # mean lat/lon.
    lat_mean = sum(latlist) / len(latlist) 
    lon_mean = sum(lonlist) / len(lonlist) 

    maclist = [ macs.split('|') for macs in mac_raw ]
    rsslist = [ rsss.split('|') for rsss in rss_raw ]

    # Ugly code for packing MAC:RSS in dictionary.
    # dictlist: [{mac1:rss1,mac2:rss2,...},{mac3:rss3,mac4:mac4,...},...]
    dictlist = []
    for i in range(len(maclist)):
        dict = {}
        for x in range(len(rsslist[i])):
            dict[maclist[i][x]] = rsslist[i][x]
        dictlist.append(dict)

    # Intersection of MAC address list for spid.
    inter = set( maclist.pop() )
    while not len(maclist) is 0:
        inter = inter & set(maclist.pop())
    # mac_interset: intersection of all MAC lists for spid samples.
    mac_interset = list(inter)

    # List the rss values of the MACs in intersection set.
    # dictlist_inters: {mac1:[rss11,rss12,...], mac2:[rss21,rss22,...],...},
    # mac_interset=[mac1, mac2,...].
    dictlist_inters = {}
    for mac in mac_interset:
        dictlist_inters[mac] = []
        for dict in dictlist:
            dictlist_inters[mac].append(int(dict[mac]))
    print 'lat_mean: %f\tlon_mean: %f' % (lat_mean, lon_mean)
    #print 'dictlist_inters: \n%s' % (dictlist_inters)

    # Packing the MACs in intersection set and corresponding rss means to fingerprint.
    # Fingerprint: spid, lat_mean, lon_mean, mac_interset_rmp, rss_interset_rmp
    # keys: MACs list of mac_interset; mrss: mean rss list of macs in keys.
    # ary_fp: array for rss sorting of mac_interset, ary_fp[0]:macs,ary_fp[1]:rsss.
    keys = dictlist_inters.keys()
    mrss = [ sum(dictlist_inters[x])/len(dictlist_inters[x]) 
            for x in dictlist_inters.keys() ]
    ary_fp = np.array(keys + mrss).reshape(2,-1)
    # The default ascending order of argsort() seems correct for finding max-rss macs here, 
    # because the respective sorted orders for strings and numbers are opposite.
    ary_fp = ary_fp[ :, np.argsort(ary_fp[1])[:CLUSTERKEYSIZE] ]
    mac_interset_rmp = '|'.join( list(ary_fp[0]) )
    rss_interset_rmp = '|'.join( list(ary_fp[1]) )
    print 'Unclustered fingerprint at sampling point [%d]: ' % spid
    if verbose:
        print 'mac_interset_rmp:rss_interset_rmp'
        pp.pprint( [mac+' : '+rss for mac,rss in zip( 
            mac_interset_rmp.split('|'), rss_interset_rmp.split('|') )] )
    else:
        print 'mac_interset_rmp: %s\nrss_interset_rmp: %s' % \
            ( mac_interset_rmp, rss_interset_rmp )

    fingerprint = [ spid, lat_mean, lon_mean, mac_interset_rmp, rss_interset_rmp, time ]
    return fingerprint


def doClusterAll(fd_csv=None):
    """
    Clustering the raw radio map fingerprints for fast indexing(mainly in db),
    generating following data structs: cid_aps, cfprints and crmp.

    Data structs
    ------------
    *cid_aps*: cluster id, keyap, and internal seqence NO of keyap in this cluster, 
        including cids(clusterids), keyaps(macs), seq(start from 1).
    *cfprints*: all clusterid-specified fingerprints,
        including cids(clusterids), lat, lon, h, rsss, time.
    *crmp*: transitional data struct for further processing like clustering or just logging,
        including cids(clusterids),spid,servid,time,imei,imsi,ua,mcc,mnc,lac,ci,rss,lat,lon,h,macs,rsss.

    Heuristics
    ----------
    (1)Offline clustering:
        visible APs >=4: clustering with top4;
        visible APs < 4: discarded.

    (2)Online declustering:
        visible APs >=4: declustering with top4, top3(if top4 fails);
        visible APs < 4: try top3 or 2 to see whether included in any cluster key AP set.
    """
    # csvdat: compatible with fpp-wpp rawdata spec, which defines the sampling data format: 
    # fpp_specs(14col), fpp_rawdata_xls(16col)
    # IMEI      0, 3
    # IMSI      1, 4
    # UA        2, 5
    # MCC       3, 6
    # MNC       4, 7
    # LAC       5, 8
    # CI        6, 9
    # rss       7, 10
    # lat       8, 11
    # lon       9, 12
    # h         10, 13
    # wlanmacs  11, 14
    # wlanrsss  12, 15
    # ver_uprecs , 16
    # area_ok    , 17
    # area_try   , 18
    # Time      13, 2
    # 
    # spid        , 0
    # servid      , 1

    csvdat = csv.reader( fd_csv )
    try:
        rawrmp = np.array([ fp for fp in csvdat ])
        num_rows,num_cols = np.shape(rawrmp)
    except csv.Error, e:
        sys.exit('\nERROR: line %d: %s!\n' % (csvdat.line_num, e))
    print 'All Clustering -> %s FPs' % num_rows
    try:
        csv_cols = CSV_CFG_RFP[num_cols]
    except KeyError:
        sys.exit('\nERROR: Unsupported csv format!\n')
    col_macs = csv_cols['macs']
    col_rsss = csv_cols['rsss']
    col_lat  = csv_cols['lat']
    col_lon  = csv_cols['lon']
    col_h    = csv_cols['h']
    col_time = csv_cols['time']
    print 'CSV format: %d fields' % num_cols
        
    # topaps: array of splited aps strings for all fingerprints.
    sys.stdout.write('\nSelecting MACs for clustering ... ')
    #print
    topaps = np.char.array(rawrmp[:,col_macs]).split('|') 
    toprss = np.char.array(rawrmp[:,col_rsss]).split('|')
    joinaps = []
    for i in xrange(len(topaps)):
        macs = np.array(topaps[i])
        rsss = np.array(toprss[i])
        idxs_max = np.argsort(rsss)[:CLUSTERKEYSIZE]
        topaps[i] = macs[idxs_max]
        joinaps.append('|'.join(topaps[i]))
        toprss[i] = '|'.join(rsss[idxs_max])
        #print toprss[i]
    #print
    rawrmp[:,col_macs] = np.array(joinaps)
    rawrmp[:,col_rsss] = np.array(toprss)
    #pp.pprint(rawrmp[:,col_macs])
    #pp.pprint(rawrmp[:,col_rsss])
    print 'Done'

    # sets_keyaps: a list of AP sets for fingerprints clustering in raw radio map,
    # [set1(ap11,ap12,...),set2(ap21,ap22,...),...].
    # lsts_keyaps: a list of AP lists for fingerprints clustering in raw radio map,
    # [[ap11,ap12,...],[ap21,ap22,...],...].
    # idxs_keyaps: corresponding line indices of the ap set in sets_keyaps.
    # [[idx11,idx12,...],[idx21,idx22,...],...].
    sets_keyaps = []
    lsts_keyaps = []
    idxs_keyaps = []

    # Clustering heuristics.
    cnt = 0
    sys.stdout.write('Fingerprints clustering ... ')
    for idx_topaps in range(len(topaps)):
        taps = topaps[idx_topaps]
        # ignore when csv record has no wlan info.
        if (len(taps) == 1) and (not taps[0]): continue
        staps = set( taps )
        if (not len(sets_keyaps) == 0) and (staps in sets_keyaps):
            idx = sets_keyaps.index(staps)
            idxs_keyaps[idx].append(idx_topaps)
            continue
        idxs_keyaps.append([])
        sets_keyaps.append(staps)
        lsts_keyaps.append(taps)
        idxs_keyaps[cnt].append(idx_topaps)
        cnt += 1
    #print 'lsts_keyaps: %s' % lsts_keyaps
    print 'Done'

    # cids: list of clustering ids for all fingerprints, for indexing in sql db.
    # [ [1], [1], ..., [2],...,... ]
    # cidtmp1: [ [1,...], [2,...], ...].
    # cidtmp2: [ 1,..., 2,..., ...].
    sys.stdout.write('Fingerprints matrix slicing ... ')
    cidtmp1 = [ [cid+1]*len(idxs_keyaps[cid]) for cid in range(len(idxs_keyaps)) ]
    cidtmp2 = []; [ cidtmp2.extend(x) for x in cidtmp1 ]
    cids = [ [x] for x in cidtmp2 ]

    ord = []; [ ord.extend(x) for x in idxs_keyaps ]
    crmp = np.append(cids, rawrmp[ord,:], axis=1)
    print 'Done'

    sys.stdout.write('Constructing clusterid-keymacs mapping table ... ')
    # cid_aps: array that mapping clusterid and keyaps for cid_aps.tbl. [cid,aps,seq].
    cidaps_idx = [ idxs[0] for idxs in idxs_keyaps ]
    cid_aps = np.array([ [str(k+1),v] for k,v in enumerate(rawrmp[cidaps_idx, [col_macs]]) ])
    # For optimized table structure of cidaps: cid, keyap, seq(start from 1).
    cid_aps_tmp = []
    for rec in cid_aps:
        aps = rec[1].split('|')
        for seq,ap in enumerate(aps):
            cid_aps_tmp.append([ rec[0], ap, seq+1 ])
    cid_aps = np.array(cid_aps_tmp)
    print 'Done'
    
    # re-arrange RSSs of each fingerprint according to its key MACs.
    # macsref: key AP MACs in cidaps table.
    # cr: clustered fingerprints data(in crmp) for each cluster.
    #print 'crmp: \n%s' % crmp
    sys.stdout.write('Re-arranging MAC-RSS for all fingerprints ... ')
    start = 0; end = 0
    for i,macsref in enumerate(lsts_keyaps):
        end = start + len(idxs_keyaps[i])
        #print 'start: %d, end: %d' % (start, end)
        if end > len(crmp)-1: cr = crmp[start:]
        else: cr = crmp[start:end]
        #print 'macsref: %s\ncr:%s' % (macsref,cr)
        # j,fpdata: jth fp data in ith cluster. 
        for j,fpdata in enumerate(cr):
            rssnew = []
            macold = fpdata[col_macs+1].split('|')
            #print 'macold: %s' % macold
            rssold = fpdata[col_rsss+1].split('|')
            rssnew = [ rssold[macold.index(mac)] for mac in macsref ]
            cr[j][col_rsss+1] = '|'.join(rssnew) 
        if end > len(crmp)-1: crmp[start:] = cr
        else: crmp[start:end] = cr
        start = end
    print 'Done'

    # cfprints: array for cfprints.tbl, [cid,lat,lon,h,rsss,time].
    sys.stdout.write('Constructing clustered fingerprint table ... ')
    cfprints = crmp[:,[0,col_lat+1,col_lon+1,col_h+1,col_rsss+1,col_time+1]]
    print 'Done'

    if verbose:
        print 'topaps:'; pp.pprint(topaps)
        print 'sets_keyaps:'; pp.pprint(sets_keyaps)
        print 'idxs_keyaps:'; pp.pprint(idxs_keyaps)
        print 'clusterids:'; pp.pprint(cids)
        print 'crmp:'; pp.pprint(crmp)
        print 'cid_aps:'; pp.pprint(cid_aps)
        print 'cfprints:'; pp.pprint(cfprints)
    #else:
    #    print 'crmp: \n%s' % crmp

    print 'Dumping DB tables:'
    #crmpfilename = rmpfile.split('.')
    #crmpfilename[1] = 'crmp'
    #crmpfilename = '.'.join(crmpfilename)

    #timestamp = strftime('-%m%d-%H%M')
    cidaps_filename = 'test/tbl/cidaps.tbl'
    cfps_filename = 'test/tbl/cfprints.tbl'

    #np.savetxt(crmpfilename, crmp, fmt='%s',delimiter=',')
    #print '\nDumping clustered fingerprints to: %s ... Done' % crmpfilename

    np.savetxt(cidaps_filename, cid_aps, fmt='%s',delimiter=',')
    print 'Clusterid-keymacs mapping table to: %s ... Done' % cidaps_filename

    np.savetxt(cfps_filename, cfprints, fmt='%s',delimiter=',')
    print 'Clustered fingerprints table to: %s ... Done\n' % cfps_filename


