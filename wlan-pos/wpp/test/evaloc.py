#!/usr/bin/env python
# collect test results and analyze the statistics of the data.
from __future__ import division
import sys
import os
import csv
import urllib2 as ul
import time
import shelve as shlv
import pprint as pp
import numpy as np

path_repo = os.path.split(os.path.abspath(__file__))[0] + '/../../../'
sys.path.append(path_repo)
sys.path.append(path_repo + 'tool')
import geo
import online as wlanpos
import config as cfg
from config import termtxtcolors as colors
#import dataviz as viz
import geolocation_api as gl


fpath = 'dat/fpp_rawdata/cmri'

boundry = 200

# reqfile format: 14 or 16 cols.
reqfile = '%s/req.csv' % fpath
# retfile format: macs,rsss,lat,lon,err
retfile = '%s/ret.csv' % fpath
retfmt = { 'ilat_cpp' : 2, 
           'ilon_cpp' : 3, 
           'ierr_cpp' : 4 
}
# columns definition for reqreterr data file and addcols structure.
# datafile format:    whole             addcols
# macs                  0,                    
# rsss                  1,      
# ref(lat,lon)          2,3,    
# cpp(lat,lon,err)      4,5,6,          
# ecpp                  7,              0,      
# ee_cpp                8,              1,      
# py(lat,lon,err)       9,10,11,        2,3,4,    
# epy                   12,             5,
# ee_py                 13,             6,
# e_cpp_py              14,             7,
# ee_cpp_py             15,             8,
# google(lat,lon,err)   16,17,18,       9,10,11
# err_google            19,             12,
# ee_google             20,             13,
                                       
algos = ('cpp','py','google')
# addcols format: err_cpp, ee_cpp, py(lat,lon,err,ep,ee), ep_cpp_py, ee_cpp_py.
idxscnt_addcols = { # [ start idx, number of columns ].
                'cpp': [0,2], 
                 'py': [2,5],
             'cpp_py': [7,2],
             'google': [9,5]
}
idxs_addcols = { # idxs of all evaluated cols in addcols.
         'err_cpp':0,     'ee_cpp':1,
          'lat_py':2,     'lon_py':3,      'pyerr':4,      'err_py':5,      'ee_py':6, 
      'err_cpp_py':7,  'ee_cpp_py':8,
      'lat_google':9, 'lon_google':10, 'googleerr':11, 'err_google':12, 'ee_google':13
}
offsets_stats = { # offsets of cols which are to be analyzed.
                'cpp': [0,1],
                 'py': [3,4],
             'google': [3,4],
}
istats_all = [ # indexs of cols which are to be analyzed.
      idxs_addcols['err_cpp'], idxs_addcols['ee_cpp'], 
      idxs_addcols['err_py'],  idxs_addcols['ee_py'], 
      idxs_addcols['err_cpp_py'], idxs_addcols['ee_cpp_py'],
      idxs_addcols['err_google'], idxs_addcols['ee_google']
]
ierr_in_istats = {'cpp':[0,1], 'py':[2,3], 'google':[4,5]}


def ratioLess(data, val):
    num = len(data)
    ratio = (np.searchsorted(data, val, side='right'))*100 / num
    return ratio


def collectData(req=None, reqfmt=None, ret=None, retfmt=None, algos=None):
    """
    req: 16/14 col raw data.
    ret: macs, rsss, cpp(lat,lon,err).
    algos: tuple of used algos, e.g. ('cpp', 'py', 'google').
    """
    sys.stdout.write('Slicing & Merging test data ... ')
    macrss = np.char.array(req[ :, [reqfmt['idx_macs'],reqfmt['idx_rsss']] ]).split('|')
    reqcols = [ reqfmt['idx_lat'], reqfmt['idx_lon'] ]

    # complete *addcols* column definition: 
    # err_cpp, ee_cpp, py(lat,lon,err,ep,ee), ep_cpp_py, ee_cpp_py, google(lat,lon,err,ep,ee).
    addcols = []; idiffs = []; atoken = None; istats = []; ipylocoks = []
    isErrinRange={'cpp': {'all':0, 'errless200':0}, 
                   'py': {'all':0, 'errless200':0}, 
               'google': {'all':0, 'errless200':0} }

    usecpp = False; usepy = False; usegoogle = False
    idx_cur = 0
    if 'cpp' in algos: 
        usecpp = True
        istats_cpp = offsets_stats['cpp']
        istats.extend(istats_cpp) # offset of istats item in cpp section of addcols.
        idx_cur += idxscnt_addcols['cpp'][1]
        retcols = [ retfmt['ilat_cpp'], retfmt['ilon_cpp'], retfmt['ierr_cpp'] ]
    if 'py' in algos: 
        usepy = True
        istats_py = (idx_cur + np.array(offsets_stats['py'])).tolist()
        istats.extend(istats_py) # offset of istats item in cpp section of addcols.
        if usecpp:
            idx_cur = idx_cur + idxscnt_addcols['py'][1] + idxscnt_addcols['cpp_py'][1]
            # reqret format: ref(lat,lon), cpp(lat,lon,err)
            reqret = np.append(req[:,reqcols], ret[:,retcols], axis=1).astype(float)
        else:
            idx_cur += idxscnt_addcols['py'][1]
            reqret = req[:,reqcols].astype(float)
    if 'google' in algos: 
        usegoogle = True
        istats_google = (idx_cur + np.array(offsets_stats['google'])).tolist()
        istats.extend(istats_google) # offset of istats item in cpp section of addcols.
    print 'Done'
    print 'istats: %s' % istats

    for icase in xrange(len(reqret)):
        macs = np.array(macrss[icase,0]) 
        rsss = np.array(macrss[icase,1])
        latref = reqret[icase,0]; lonref = reqret[icase,1] 
        addcol = []
        if usecpp:
            latcpp = reqret[icase,2]; loncpp = reqret[icase,3]; cpperr = reqret[icase,4] 

            # cpploc error to refloc.
            err_cpp = geo.dist_km(loncpp, latcpp, lonref, latref)*1000
            addcol.append(err_cpp)
            # cpp error estimation error.
            ee = cpperr - err_cpp 
            if ee >= 0: 
                isErrinRange['cpp']['all'] += 1
                if err_cpp <= 200:
                    isErrinRange['cpp']['errless200'] += 1
            ee_cpp = abs(ee)/cpperr
            addcol.append(ee_cpp)
        if usepy:
            # pyloc result.
            num_visAPs = len(macs)
            INTERSET = min(cfg.CLUSTERKEYSIZE, num_visAPs)
            idxs_max = np.argsort(rsss)[:INTERSET]
            mr = np.vstack((macs, rsss))[:,idxs_max]
            pyloc = wlanpos.fixPos(INTERSET, mr, verb=False)
            if not pyloc: continue
            ipylocoks.append(icase)
            addcol.extend(pyloc)
            # pyloc error to refloc.
            err_py = geo.dist_km(pyloc[1], pyloc[0], lonref, latref)*1000
            addcol.append(err_py)
            # py error estimation error.
            ee = pyloc[2] - err_py 
            if ee >= 0: 
                isErrinRange['py']['all'] += 1
                if err_py <= 200:
                    isErrinRange['py']['errless200'] += 1
            ee_py = abs(ee)/pyloc[2]
            addcol.append(ee_py)
            if usecpp:
                # pyloc error to cpploc.
                err_cpp_py = geo.dist_km(pyloc[1], pyloc[0], loncpp, latcpp)*1000
                addcol.append(err_cpp_py)
                # error between cpploc error & pyloc error.
                ee_cpp_py = abs(err_cpp - err_py)
                addcol.append(ee_cpp_py)
                if err_cpp_py or ee_cpp_py: idiffs.append(icase)
        if usegoogle:
            # google location api results.
            mr = mr.tolist()
            # Old interface of makeReq.
            #gloc_req = gl.makeReq(wlans=mr, atoken=atoken)
            wlans = []
            for iwlan,mac in enumerate(mr[0]):
                wlan = {}
                wlan['mac_address'] = mac
                wlan['signal_strength'] = mr[1][iwlan]
                wlans.append(wlan)
            gloc_req = gl.makeReq(wlans=wlans, atoken=atoken)
            gloc_ret = gl.getGL(gloc_req)
            gloc_pos = gloc_ret['location']
            if (not atoken) and ('access_token' in gloc_ret):
                atoken = gloc_ret['access_token']
            addcol.extend( gloc_pos.values() )
            # google loc error to refloc.
            err_google = geo.dist_km(gloc_pos['longitude'], gloc_pos['latitude'], lonref, latref)*1000
            addcol.append(err_google)
            # google loc error estimation error.
            ee = gloc_pos['accuracy'] - err_google 
            if ee >= 0: 
                isErrinRange['google']['all'] += 1
                if err_google <= 200:
                    isErrinRange['google']['errless200'] += 1
            ee_google = abs(ee)/gloc_pos['accuracy']
            addcol.append(ee_google)
        print '%d: %s' % (icase+1, addcol)
        addcols.append(addcol)
        print 

    return (addcols, isErrinRange, reqret, ipylocoks, istats, idiffs)


def chkFmt(data=None):
    """
    data: np styled array.
    """
    num_cols = np.shape(data)[1]
    col1, col2 = data[0,:2]
    colfmt = {}
    # reqreterr format starts with macs and rsss.
    num_macs = col1.count('|') + 1
    num_colons = col1.count(':') 
    if num_colons == (num_macs)*5:
        if num_cols == 21 or num_cols == 16:
            colfmt['idx_macs'] = 0 
            colfmt['idx_rsss'] = 1
            colfmt['idx_lat'] = 2
            colfmt['idx_lon'] = 3
            colfmt['ilat_cpp'] = 4
            colfmt['ilon_cpp'] = 5
            colfmt['ierr_cpp'] = 6
        elif num_cols == 5:
            colfmt['idx_macs'] = 0 
            colfmt['idx_rsss'] = 1
            colfmt['ilat_cpp'] = 2
            colfmt['ilon_cpp'] = 3
            colfmt['ierr_cpp'] = 4
        else: sys.exit('\nERROR: Unsupported req/ret/err csv format!\n')
    else:
        if num_cols == 14:
            colfmt['idx_macs'] = 11 
            colfmt['idx_rsss'] = 12
            colfmt['idx_lat'] = 8 
            colfmt['idx_lon'] = 9
        elif num_cols == 16:
            colfmt['idx_macs'] = 14 
            colfmt['idx_rsss'] = 15
            colfmt['idx_lat'] = 11
            colfmt['idx_lon'] = 12
        else: sys.exit('\nERROR: Unsupported fpp/wpp rawdata csv format!\n')
    print '%d fields' % num_cols
    return colfmt


def getIPaddr(ifname='eth0'):
    """
    return: ips: {'ifname':'ipaddr'}
    """
    use_netifs = False
    try:
        import netifaces as nifs
        use_netifs = True
    except ImportError:
        #pass
        import socket as sckt
        import fcntl
        import struct

    if not use_netifs:
        s = sckt.socket(sckt.AF_INET, sckt.SOCK_DGRAM)
        addr = sckt.inet_ntoa(fcntl.ioctl(
                                s.fileno(),
                                0x8915,  # SIOCGIFADDR
                                struct.pack('256s', ifname[:15]) )[20:24])
        ips = {ifname: addr}
    else:
        ips = {}
        inet_id = nifs.AF_INET
        ifaces = nifs.interfaces()
        ifaces.remove('lo')
        for iface in ifaces:
            ifaddrs = nifs.ifaddresses(iface)
            if inet_id in ifaddrs: 
                inets = ifaddrs[inet_id]
                if len(inets) == 1:
                    ips[iface] = inets[0]['addr']
                else:
                    for idx,inet in enumerate(inets):
                      ips[iface] = {}
                      ips[iface][idx] = inet['addr']
    return ips


def main():
    arglen = len(sys.argv)
    if (not arglen==1) and (not arglen==2):
        sys.exit('\nPlease type: %s [label]\n' % (sys.argv[0]))
    else:
        if arglen == 2: 
            label = sys.argv[1]
        else: 
            label = 'urban'

    reqin = csv.reader( open(reqfile,'r') )
    retin = csv.reader( open(retfile,'r') )
    req = np.array([ line for line in reqin ])
    ret = np.array([ line for line in retin ])

    print 'Checking CSV format: '
    if len(req) == len(ret): 
        sys.stdout.write('req: ')
        colfmt_req = chkFmt(req)  
        sys.stdout.write('ret: ')
        colfmt_ret = chkFmt(ret) 
    else: 
        sys.exit('\nERROR: Not matched req/ret files: \n%s\n%s!\n' % (reqfile, retfile))
    print

    #algos = ('cpp', 'py', 'google')
    #algos = ('py', 'google')
    #algos = ('cpp', 'py')
    algos = ('py',)

    # Proxy Setting(buggy).
    if 'google' in algos:
        ipaddr = getIPaddr()
        if 'eth0' in ipaddr: ipaddr = [ ipaddr['eth0'] ]
        else: ipaddr = ipaddr.values()
        for ip in ipaddr: 
            if ip.split('.')[0] == '10': 
                gl.setConn()
                break

    print 'Reconstructing data matrix: macrss/refloc/%s ... ' % '/'.join(algos)
    # build data matrix with online google geolocation api request.
    addcols, errin, reqret, ipyoks, istats, idiffs_cpp_py = collectData(req=req, reqfmt=colfmt_req, 
                                                            ret=ret, retfmt=colfmt_ret, algos=algos)
    addcols = np.array( addcols )

    # build data matrix with offline csv data file.
    #print 'Loading data matrix...'
    #reqreterr_csv = csv.reader( open('test.csv','r') )
    ## 7: start idx of addcols in reqreterr.
    #addcols = np.array([ line for line in reqreterr_csv ])[:,7:].astype(float) 


    num_all = len(addcols) 
    print 'Test count: %d' % num_all

    stats = {}; idx_cur = 0; is_list = range(len(istats))
    for algo in algos:
        stats[algo] = {}

        idx_end = idx_cur + len(offsets_stats[algo])
        idx_ep, idx_ee = is_list[idx_cur:idx_end]
        idxs_epee = {'ep':idx_ep, 'ee':idx_ee}
        idx_cur = idx_end

        epdata = addcols[:,istats[idx_ep]]
        eedata = addcols[:,istats[idx_ee]]

        idx_sort_ep = np.argsort(epdata)
        epdata_sort = epdata[idx_sort_ep]

        idx_sort_ee = np.argsort(eedata)
        eedata_sort = eedata[idx_sort_ee]

        idx_errless200_ep = np.searchsorted(epdata_sort, boundry)
        idx_sort200_ep = idx_sort_ep[:idx_errless200_ep]

        epdata_200 = epdata[idx_sort200_ep]
        idx_sort_ep200 = np.argsort(epdata_200)
        epdata_200_sort = epdata_200[idx_sort_ep200]

        eedata_200 = eedata[idx_sort200_ep]
        idx_sort_ee200 = np.argsort(eedata_200)
        eedata_200_sort = eedata_200[idx_sort_ee200]

        datasets = { 'all':{'ep':epdata_sort,     'ee':eedata_sort}, 
              'errless200':{'ep':epdata_200_sort, 'ee':eedata_200_sort} }
        for type in datasets:
            dataset = datasets[type]
            stats[algo][type] = {}
            for item in dataset:
                idx_e = idxs_epee[item]
                data_sort = dataset[item]
                if not np.any(data_sort): continue
                num_test = len(data_sort)
                stats[algo][type][item] = {}
                stats[algo][type][item]['mean'] = '%.2f'%(np.mean(data_sort))
                stats[algo][type][item]['std']  = '%.2f'%(np.std(data_sort))
                stats[algo][type][item]['max']  = '%.2f'%(data_sort[-1])
                stats[algo][type][item]['ratio67'] = '%.2f'%(data_sort[int(num_test*.67)])
                stats[algo][type][item]['ratio95'] = '%.2f'%(data_sort[int(num_test*.95)])
                if item == 'ep':
                    stats[algo][type][item]['ratioless50']  = '%.2f%%'%(ratioLess(data_sort, 50))
                    stats[algo][type][item]['ratioless100'] = '%.2f%%'%(ratioLess(data_sort, 100))
                    #print 'plot: %s_%s_%s_%s' % (label, algo, type, item)
                    #viz.pyplotCDF(data_sort, '%s_%s_%s_%s'%(label, algo, type, item))
                elif item == 'ee':
                    stats[algo][type][item]['inrange'] = '%.2f%%'%(errin[algo][type]*100/num_test)

    pp.pprint(stats)
    sys.exit(0)


    # data/log file config.
    timestamp = time.strftime('%Y%m%d-%H%M%S')
    datafile = '%s/reqreterr_wpp_%s_%s.csv' % (fpath, label, timestamp)
    statsfile = '%s/stats_wpp_%s_%s.log' % (fpath, label, timestamp)

    # shelved data dumping.
    stats_dict = shlv.open(statsfile)
    for algo in algos:
        stats_dict[algo] = stats[algo]
    stats_dict.close()
    print 'stats results shelved into %s' % statsfile
    # shelved data reading.
    #stats_dict = dict(shlv.open(statsfile))
    #pp.pprint(stats_dict)

    reqreterr = np.append(reqret[ipyoks], addcols, axis=1)
    req = req[ipyoks,:]
    reqreterr = np.append(req[ :, [colfmt_req['idx_macs'],colfmt_req['idx_rsss']] ], reqreterr, axis=1)

    np.savetxt(datafile, reqreterr, fmt='%s',delimiter=',')
    print '\nDumping all req/ret/err to: %s ... Done' % datafile

    if len(algos) > 1:
        diffile = '%s/diffs_wpp_%s_%s.csv' % (fpath, label, timestamp)
        diffs = reqreterr[idiffs_cpp_py,:]
        print 'diff data: %d' % len(idiffs_cpp_py)

        np.savetxt(diffile, diffs, fmt='%s',delimiter=',')
        print '\nDumping diff req/ret/err to: %s ... Done' % diffile

    #errs_sort = [ [x] for x in errs_sort ]
    #np.savetxt('errsort.dat', errs_sort, fmt='%s',delimiter=',')


if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(collectData)
        psyco.bind(chkFmt)
        psyco.bind(ratioLess)
        psyco.bind(getIPaddr)
        psyco.bind(wlanpos.fixPos)
        psyco.bind(geo.dist_km)
        psyco.bind(viz.pyplotCDF)
        psyco.bind(gl.makeReq)
        psyco.bind(gl.getGL)
        psyco.bind(gl.setConn)
    except ImportError:
        pass

    main()
