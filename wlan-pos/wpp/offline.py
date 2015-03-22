#!/usr/bin/env python
# encoding: utf-8
from __future__ import division
import os
import sys
import csv
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from time import strftime, ctime, sleep
from numpy import array as np_array, append as np_append
from pprint import pprint, PrettyPrinter
from bz2 import BZ2File
from ftplib import FTP

from wpp.config import DB_OFFLINE, sqls, dbsvrs, mailcfg, errmsg, FTPCFG, \
        DATPATH, RAWSUFFIX#, RMPSUFFIX, CLUSTERKEYSIZE
from wpp.db import WppDB
from wpp.fingerprint import doClusterIncr, doClusterAll#, genFPs
from wpp.util.net import getIP, sendMail
from wpp.util.geolocation_api import googleAreaLocation
from wpp.util.wlan import scanWLAN_RE


def usage():
    print """
offline.py - Copyleft 2009-%s Yan Xiaotian, xiaotian.yan@gmail.com.
Offline work for WLAN location fingerprinting.

usage:
    <sudo> offline <option> <infile>
option:
    -a --areacrawl         :  Crawl laccid~area location data from google api.
    -c --cluster=<type id> :  Fingerprints clustering, type_id: 1-All,2-Incr.
    -d --db=<dbfiles>      :  Specify the db files to upload.
    -f --floor             :  Floor number for indoor scan.
    -h --help              :  Show this help.
    -i --spid=<spid>       :  Sampling point id.
    -k --kml=<cfprints.tbl>:  Generate KML format from cfprints table file.
    -m --mode=<mode id>    :  Indicate the processing mode: 1-all; 2-incr.
    -n --no-dump           :  No data dumping to file.
    -r --rawdata=<rawfile> :  Load rawdata into WppDB, including algo tables. 
                              1)db.initTables(), db.updateIndexes(); 
                              2)doClusterIncr(), under certain mode(specify
                              with -m, default=all).
    -s --scan              :  Scan FP data and write to certain storage(file,db). 
    -t --to-rmp=<rawfile>  :  Process the given raw data to radio map. 
    -u --updatedb=<mode>   :  Update algo data with synced rawdata from remote FTP.
    -v --verbose           :  Verbose mode.
NOTE:
    <rawfile> needed by -t/--to-rmp option must NOT have empty line(s)!
""" % strftime('%Y')


def genKMLfile(cfpsfile):
    """
    Generating KML format file with data in cfps sql table file.
    format of cfps table file:
    cluster id, spid, lat, lon, keyrsss
    """
    from wpp.util.kml import genKML
    from wpp.config import icon_types
    cfpsin = csv.reader( open(cfpsfile,'r') )
    cfps = np_array([ cluster for cluster in cfpsin ])[:,:4]
    cfps = [ [[ c[2], c[3], c[1], 'cluster:%s, spid:%s'%(c[0],c[1]) ]] for c in cfps ]
    if verbose: pp.pprint(cfps)
    else: print cfps
    kfile = 'kml/ap.kml'
    #homedir = os.path.expanduser('~')
    for type in icon_types:
        icon_types[type][1] = os.getcwd() + icon_types[type][1]
    genKML(cfps, kmlfile=kfile, icons=icon_types)

def read_num(default=None, prompt='Input: '):
    num = raw_input(prompt)
    try:
        num = int(num)
    except ValueError:
        num = default
    return num

def collectFPs():
    """
    Collecting FPs consist of WLAN scanning data & Coordinate.
    *return: fp = [ iac, h, time, mac1|mac2, rss1|rss2 ]
    """
    # Indoor scan when floor is not False
    indoor = True
    if floor is False:
        from wpp.util.gps import getGPS
        indoor = False

    while True:
        print '='*50
        try:
            iac = raw_input('IAC: ')
        except KeyboardInterrupt:
            print '\nBye.'
            sys.exit(0)
        loops = read_num(default=40, prompt='Loops(default 40): ')
        delay = read_num(default=1, prompt='Delay(default 1s): ')
        fps = []
        for i in range(loops):
            if indoor:
                fp = [ iac, floor ]
            else:
                fp = getGPS()
            fp.append( strftime('%Y%m%d-%H%M%S') )

            # wlan: [ [ mac1, rss1 ], [ mac2, rss2 ], ... ]
            wlan = scanWLAN_RE()
            print 'Scan %2s --> %s + %s APs' % (i+1, fp, len(wlan))
            # Judging whether the number of scanned wlan APs more than 4 is for clustering.
            #if wlan and (len(wlan) >= CLUSTERKEYSIZE): num_fields = len(wlan[0])
            if wlan: num_fields = len(wlan[0])
            else: return fp

            # Raw data: time, lat, lon, mac1|mac2, rss1|rss2
            # aps: [ [mac1, mac2], [rss1, rss2] ]
            # aps_raw: [ mac1|mac2, rss1|rss2 ]
            if not num_fields == 0:
                aps = [ [ ap[i] for ap in wlan ] for i in range(num_fields) ]
                aps_raw = [ '|'.join(ap) for ap in aps ]
                fp.extend(aps_raw)

            fps.append(fp)
            sleep(1)
        # Raw data dumping to file.
        if nodump is False:
            if not os.path.isdir(DATPATH):
                try:
                    os.umask(0) #linux system default umask: 022.
                    os.mkdir(DATPATH,0777)
                    #os.chmod(DATPATH,0777)
                except OSError, errmsg:
                    print "Failed: %d" % str(errmsg)
                    sys.exit(99)
            date = strftime('%Y-%m%d')
            fp_filename = DATPATH + 'rawfp_' + date + RAWSUFFIX
            dumpCSV(fp_filename, fps)
    # Scan Summary.
    #print '\nOK/Total:%28d/%d\n' % (times-tfail, times)


def dumpCSV(csvfile, content):
    """
    Appendding csv-formed content line(s) into csvfile.
    """
    if not content: print 'dumpCSV: Null content!'; sys.exit(99)
    print 'Dumping data to %s' % csvfile
    csvout = csv.writer( open(csvfile,'a') )
    if not isinstance(content[0], list): content = [ content ]
    csvout.writerows(content)


def syncFtpUprecs(ftpcfg=None, ver_wpp=None):
    """
    ftpcfg: connection string.
    ver_wpp:  current wpp version of rawdata.
    vers_fpp: fpp rawdata versions needed for wpp.
    localbzs: local path(s) of rawdata bzip2(s).
    """
    ftp = FTP()
    #ftp.set_debuglevel(1)
    try:
        print ftp.connect(host=ftpcfg['ip'],port=ftpcfg['port'],timeout=ftpcfg['timeout'])
    except:
        sys.exit("FTP Connection Failed: %s@%s:%s !" % (ftpcfg['user'],ftpcfg['ip'],ftpcfg['port']))
    print ftp.login(user=ftpcfg['user'],passwd=ftpcfg['passwd'])
    print ftp.cwd(ftpcfg['path'])
    files = ftp.nlst()
    # Naming rule of bzip2 file: FPP_RawData_<hostname>_<ver>.csv.bz2
    try:
        bz2s_latest = [ f for f in files if f.endswith('bz2') 
                and (f.split('_')[-1].split('.')[0]).isdigit()
                and int(f.split('_')[-1].split('.')[0])>ver_wpp ]
    except ValueError:
        sys.exit('\nERROR: Rawdata bz2 file name should be: \nFPP_RawData_<hostname>_<ver>.csv.bz2!')
    localbzs = []
    for bz2 in bz2s_latest:
        cmd = 'RETR %s' % bz2
        localbz = '%s/%s' % (ftpcfg['localdir'], bz2)
        fd_local = open(localbz, 'wb')
        ftp.retrbinary(cmd, fd_local.write)
        fd_local.close()
        localbzs.append(localbz)
    #ftp.set_debuglevel(0)
    print ftp.quit()
    vers_fpp = [ int(f.split('_')[-1].split('.')[0]) for f in bz2s_latest ]
    return (vers_fpp,localbzs)


def updateAlgoData():
    """
    Update from raw data into FPs directly used by location.fixPosWLAN() from WppDB(wpp_clusterid, wpp_cfps).
    1) Retrieve latest incremental rawdata(csv) from remote FTP server(hosted by FPP).
    2) Decompress bzip2, import CSV into wpp_uprecsinfo with its ver_uprecs, Update ver_uprecs in wpp_uprecsver.
    3) Incr clustering inserted rawdata for direct algo use.
    """
    dbips = DB_OFFLINE
    for dbip in dbips:
        dbsvr = dbsvrs[dbip]
        wppdb = WppDB(dsn=dbsvr['dsn'], dbtype=dbsvr['dbtype'])
        ver_wpp = wppdb.getRawdataVersion()
        # Sync rawdata into wpp_uprecsinfo from remote FTP server.
        print 'Probing rawdata version > [%s]' % ver_wpp
        vers_fpp,localbzs = syncFtpUprecs(FTPCFG, ver_wpp)
        if not vers_fpp: print 'Not found!'; continue
        else: print 'Found new vers: %s' % vers_fpp
        # Handle each bzip2 file.
        alerts = {'vers':[], 'details':''}
        tab_rd = 'wpp_uprecsinfo'
        for bzfile in localbzs:
            # Filter out the ver_uprecs info from the name of each bzip file.
            ver_bzfile = bzfile.split('_')[-1].split('.')[0]
            # Update ver_uprecs in wpp_uprecsver to ver_bzfile.
            wppdb.setRawdataVersion(ver_bzfile)
            print '%s\nUpdate ver_uprecs -> [%s]' % ('-'*40, ver_bzfile)
            # Decompress bzip2.
            sys.stdout.write('Decompress & append rawdata ... ')
            csvdat = csv.reader( BZ2File(bzfile) )
            try:
                indat = np_array([ line for line in csvdat ])
            except csv.Error, e:
                sys.exit('\n\nERROR: %s, line %d: %s!\n' % (bzfile, csvdat.line_num, e))
            # Append ver_uprecs(auto-incr),area_ok(0),area_try(0) to raw 16-col fp.
            append_info = np_array([ [ver_bzfile,0,0] for i in xrange(len(indat)) ])
            indat_withvers = np_append(indat, append_info, axis=1).tolist(); print 'Done'
            # Import csv into wpp_uprecsinfo.
            try:
                sys.stdout.write('Import rawdata: ')
                wppdb.insertMany(table_name=tab_rd, indat=indat_withvers, verb=True)
            except Exception, e:
                _lineno = sys._getframe().f_lineno
                _file = sys._getframe().f_code.co_filename
                alerts['details'] += '\n[ver:%s][%s:%s]: %s' % \
                        (ver_bzfile, _file, _lineno, str(e).replace('\n', ' '))
                alerts['vers'].append(ver_bzfile)
                print 'ERROR: Insert Rawdata Failed!'
                continue
            # Incr clustering. 
            # file described by fd_csv contains all *location enabled* rawdata from wpp_uprecsinfo.
            strWhere = 'WHERE lat!=0 and lon!=0 and ver_uprecs=%s' % ver_bzfile
            cols_ignored = 3  # 3 status cols to be ignored during clustering: ver_uprecs,area_ok,area_try.
            cols_select = ','.join(wppdb.tbl_field[tab_rd][:-cols_ignored])
            sql = wppdb.sqls['SQL_SELECT'] % ( cols_select, '%s %s'%(tab_rd,strWhere) )
            rdata_loc = wppdb.execute(sql=sql, fetch_one=False)
            if not rdata_loc: continue    # NO FPs has location info.
            str_rdata_loc = '\n'.join([ ','.join([str(col) for col in fp]) for fp in rdata_loc ])
            fd_csv = StringIO(str_rdata_loc)
            print 'FPs for Incr clustering selected & ready'
            n_inserts = doClusterIncr(fd_csv=fd_csv, wppdb=wppdb, verb=False)
            print 'AlgoData added: [%s] clusters, [%s] FPs' % (n_inserts['n_newcids'], n_inserts['n_newfps'])
        # Move rawdata without location to another table: wpp_uprecs_noloc.
        tab_rd_noloc = 'wpp_uprecs_noloc'
        strWhere = 'lat=0 or lon=0'
        sql = wppdb.sqls['SQL_INSERT_SELECT'] % ( tab_rd_noloc, '*', '%s WHERE %s'%(tab_rd,strWhere) )
        wppdb.cur.execute(sql)
        sql = wppdb.sqls['SQL_DELETE'] % (tab_rd, strWhere)
        wppdb.cur.execute(sql)
        wppdb.close()
        print 'Move noloc rawdata -> |%s|' % tab_rd_noloc
        if alerts['vers']:
            # Send alert email to admin.
            _func = sys._getframe().f_code.co_name
            subject = "[!]WPP ERROR: %s->%s, ver: [%s]" % (_file, _func, ','.join(alerts['vers']))
            body = ( errmsg['db'] % (tab_rd,'insert',alerts['details'],getIP()['eth0'],ctime()) ).decode('utf-8')
            print alerts['details']
            print subject#, body
            print 'Sending alert email -> %s' % mailcfg['to']
            sendMail(mailcfg['from'],mailcfg['userpwd'],mailcfg['to'],subject,body)

def crawlAreaLocData():
    """
    1) fetch 100 records with flag area_ok = 0.
    2) try areaLocation(laccid), if OK, then update flag area_ok =1 and quit; else goto 2).
    3) try googleAreaLocation(latlon), if OK, then get geoaddr:[province,city,district]; 
       else |wpp_uprecsinfo|.area_try += 1 and quit.
    4) search area_code for the found district, insert area location 
       (laccid,areacode,areaname_cn) into |wpp_cellarea|, and update flag area_ok = 1.
    """
    fail_history = {}
    dbips = DB_OFFLINE
    for dbip in dbips:
        dbsvr = dbsvrs[dbip]
        wppdb = WppDB(dsn=dbsvr['dsn'], dbtype=dbsvr['dbtype'])
        # select config.CRAWL_LIMIT raw fps which haven't tried for google area location.
        fps_noarea = wppdb.getCrawlFPs()
        for fp in fps_noarea:
            # try areaLocation(laccid)
            laccid = '%s-%s' % (fp[8], fp[9])
            if laccid in fail_history: continue
            time = fp[2]
            print laccid, time
            if wppdb.areaLocation(laccid):
                # area_ok = 1 & quit.
                wppdb.setUprecsAreaStatus(status=1, time=time)
            else:
                print fp
                # try google area location.
                geoaddr = googleAreaLocation( latlon=(fp[11], fp[12]) )
                # area_try += 1 & quit
                wppdb.setUprecAreaTry(area_try=fp[18]+1, time=time)
                if geoaddr:
                    # insert area location info(laccid~geoaddr) into |wpp_cellarea|.
                    # till now, area_location: 'laccid,area_code,province>city>district'.
                    area_location = wppdb.addAreaLocation(laccid=laccid, geoaddr=geoaddr)
                    if not area_location:
                        if not laccid in fail_history: 
                            fail_history[laccid] = geoaddr 
                        print 'Failed to add area location: [%s] for cell[%s]' % \
                              (geoaddr[-1].encode('utf8'), laccid)
                        continue
                    # area_ok = 1 & quit.
                    wppdb.setUprecsAreaStatus(status=1, time=time)
                    print area_location.encode('utf8')  # encode('utf8') for crontab.
                else:
                    if geoaddr is None: sys.exit(0)  # OVER_QUERY_LIMIT.
                    else: pass
        #if fail_history:
        #    print fail_history


def loadRawdata(rawfile=None, updbmode=1):
    """
    rawfile: rawdata csv file.
    updbmode: update db mode: 1-all, 2-incr.

    Init *algo* tables with rawdata csv(16 columns) -- SLOW if csv is big, 
        try offline.doClusterAll(rawdata) -> db.loadClusteredData() instead.
    1) db.initTables(): init db tables if update all the db data.
    2) db.updateIndexes(): update tables indexes, drop old idxs if only update db incrementally.
    3) offline.doClusterIncr(): incremental clustering.
    """
    dbips = DB_OFFLINE
    doflush = True
    for dbip in dbips:
        dbsvr = dbsvrs[dbip]
        wppdb = WppDB(dsn=dbsvr['dsn'], dbtype=dbsvr['dbtype'])
        if updbmode == 1:
            # Create WPP tables.
            wppdb.initTables(doDrop=True)
            doflush = False
        # Update indexs.
        wppdb.updateIndexes(doflush)
        # Load csv clustered data into DB tables.
        n_inserts = doClusterIncr(fd_csv=file(rawfile), wppdb=wppdb)
        print 'Added: [%s] clusters, [%s] FPs' % (n_inserts['n_newcids'], n_inserts['n_newfps'])
        # Init ver_uprecs in |wpp_uprecsver| if it's empty.
        if wppdb.getRawdataVersion() is None: 
            wppdb.setRawdataVersion('0')
        wppdb.close()


def main():
    import getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ac:f:hi:k:m:nr:st:uv",
            ["areacrawl","cluster","floor=","help","spid=","kml=","mode=","no-dump",
             "rawdata","scan","to-rmp=","updatedb","verbose"])
    except getopt.GetoptError:
        usage()
        sys.exit(99)

    if not opts: usage(); sys.exit(0)

    # global vars init.
    crawl_area=False; updatedb=False; doLoadRawdata=False; scan=False
    #spid=0; tormp=False; tfail=0; dokml=False; 
    rawfile=None; docluster=False; updbmode=1
    global verbose,pp,floor,nodump
    verbose=False; pp=None; nodump=False; floor=False

    for o,a in opts:
        if o in ("-a", "--areacrawl"):
            crawl_area = True
        elif o in ("-c", "--cluster"):
            if not a.isdigit(): 
                print '\ncluster type: %s should be an INTEGER!' % str(a)
                usage(); sys.exit(99)
            else:
                # 1-All; 2-Incr.
                cluster_type = int(a)
                docluster = True
                rmpfile = sys.argv[3]
                if not os.path.isfile(rmpfile):
                    print 'Raw data file NOT exist: %s!' % rmpfile
                    sys.exit(99)
        #elif o in ("-i", "--spid"):
        #    if a.isdigit(): spid = int(a)
        #    else:
        #        print '\nspid: %s should be an INTEGER!' % str(a)
        #        usage(); sys.exit(99)
        elif o in ("-m", "--mode"):
            if a.isdigit(): 
                updbmode = int(a)
                if not (1 <= updbmode <= 2):
                    print '\nError: updatedb mode: (%d) NOT supported yet!' % updbmode
                    usage(); sys.exit(99)
            else:
                print '\nmode: %s should be an INTEGER!' % str(a)
                usage(); sys.exit(99)
        elif o in ("-r", "--rawdata"):
            if not os.path.isfile(a):
                print 'Rawdata file NOT exist: %s' % a
                sys.exit(99)
            else: 
                doLoadRawdata = True
                rawfile = a
        elif o in ("-s", "--scan"):
            scan = True
        #elif o in ("-t", "--to-rmp"):
        #    if not os.path.isfile(a):
        #        print 'Raw data file NOT exist: %s' % a
        #        sys.exit(99)
        #    else: 
        #        tormp = True
        #        rawfile = a
        #elif o in ("-k", "--kml"):
        #    if not os.path.isfile(a):
        #        print 'cfprints table file NOT exist: %s' % a
        #        sys.exit(99)
        #    else: 
        #        dokml = True
        #        cfpsfile = a
        #elif o in ("-n", "--no-dump"):
        #    nodump = True
        elif o in ("-f", "--floor"):
            if a.isdigit(): 
                floor = int(a)
            else:
                print '\nfloor: %s should be an INTEGER!\n' % str(a)
                usage(); sys.exit(99)
        elif o in ("-u", "--updatedb"):
            updatedb = True
        elif o in ("-v", "--verbose"):
            verbose = True
            pp = PrettyPrinter(indent=2)
        elif o in ("-h", "--help"):
            usage(); sys.exit(0)
        else:
            print 'Parameter NOT supported: %s' % o
            usage(); sys.exit(99)

    if doLoadRawdata:
        loadRawdata(rawfile, updbmode)

    # Update Algorithm related data.
    if updatedb:
        updateAlgoData()

    if crawl_area:
        crawlAreaLocData()

    # Ordinary fingerprints clustering.
    if docluster:
        if cluster_type   == 1: 
            doClusterAll(file(rmpfile))
        elif cluster_type == 2: 
            dbips = DB_OFFLINE
            for dbip in dbips:
                dbsvr = dbsvrs[dbip]
                wppdb = WppDB(dsn=dbsvr['dsn'], dbtype=dbsvr['dbtype'])
                n_inserts = doClusterIncr(fd_csv=file(rmpfile), wppdb=wppdb)
                print 'Added: [%s] clusters, [%s] FPs' % (n_inserts['n_newcids'], n_inserts['n_newfps'])
                wppdb.close()
        else: sys.exit('Unsupported cluster type code: %s!' % cluster_type)

    # KML generation.
    #if dokml:
    #    genKMLfile(cfpsfile)

    ## Raw data to fingerprint convertion.
    #if tormp:
    #    fingerprint = []
    #    fingerprint = genFPs(rawfile)
    #    if not fingerprint:
    #        print 'Error: Fingerprint generation FAILED: %s' % rawfile
    #        sys.exit(99)
    #    if nodump is False:
    #        if not rawfile == None: 
    #            date = strftime('%Y-%m%d')
    #            rmpfilename = DATPATH + date + RMPSUFFIX
    #            dumpCSV(rmpfilename, fingerprint)
    #            print '-'*65
    #            sys.exit(0)
    #        else:
    #            usage(); sys.exit(99)
    #    else:
    #        if verbose: pp.pprint(fingerprint)
    #        else: print fingerprint
    #        sys.exit(0)

    # WLAN scan for FP raw data collection.
    if scan:
        collectFPs()


if __name__ == "__main__":
    main()
