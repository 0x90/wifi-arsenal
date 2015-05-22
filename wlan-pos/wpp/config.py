#-*- encoding=utf8 -*-
import os
import sys
import redis

DATPATH = 'dat/'
LOCPATH = DATPATH+ 'loc/'
RAWSUFFIX = '.rfp'
RMPSUFFIX = '.rmp'
LOCSUFFIX = '.loc'
CLUSTERKEYSIZE = 4
KNN = 4
KWIN = 1.25
RADIUS = 6372797  # meter
MAX_AREA_TRY = 200
CRAWL_LIMIT = 5000
GOOG_AVAIL = True
DEBUG_ALGO = False
GOOG_ERR_LIMIT = 300
GOOG_FAIL_LIMIT = 25
GOOG_FAIL_CACHE_TIME = 3600*24
IP_CACHE_REDIS = '192.168.109.56'
PORT_CACHE_REDIS = 6379

# Raw FP CSV column config.
CSV_CFG_RFP = {
    14 : { 'lat'  : 8, 
           'lon'  : 9, 
           'h'    : 10,
           'macs' : 11, 
           'rsss' : 12,
           'time' : 13, },
    16 : { 'lat'  : 11, 
           'lon'  : 12, 
           'h'    : 13,
           'macs' : 14, 
           'rsss' : 15,
           'time' : 2, },
     6 : { 'iac'  : 0, 
           'h'    : 1,
           'bid'  : 2,
           'time' : 3, 
           'macs' : 4, 
           'rsss' : 5, },
}
FP_FIELD_NAMES = {
    'outdoor' : [ 'lat', 'lon', 'h', 'rsss', 'time' ],
     'indoor' : [ 'iac', 'h', 'bid', 'time', 'rsss' ]
}

# Logging related cfg.
from logging import getLogger, Formatter, INFO, DEBUG
from cloghandler import ConcurrentRotatingFileHandler as cLogRotateFileHandler
WPPLOG_FMT = '[%(asctime)s][P:%(process)s][%(levelname)s] %(message)s'  # Outdoor.
#WPPLOG_FMT = '[%(asctime)s][%(levelname)s] %(message)s'                # Indoor.
WPPLOG_FILE = 'wpp.log'        # Outdoor.
#WPPLOG_FILE = 'wpp_indoor.log'  # Indoor.
wpplog = getLogger('wpp')
wpplog.setLevel(DEBUG)
logfmt = Formatter(WPPLOG_FMT)
logdir = '%s/tmp/log' % os.environ['HOME']
logfile = '%s/%s' % (logdir, WPPLOG_FILE)
if not os.path.isfile(logfile):
    if not os.path.isdir(logdir):
        try:
            os.mkdir(logdir, 0755)
        except OSError, errmsg:
            print "Failed to mkdir: %s, %s!" % (logdir, str(errmsg))
            sys.exit(99)
    open(logfile, 'w').close()
loghandler = cLogRotateFileHandler(logfile, "a", 30*1024*1024, 200) # Rotate after 30M, keep 200 old copies.
loghandler.setFormatter(logfmt)
wpplog.addHandler(loghandler)

mc = redis.Redis(host=IP_CACHE_REDIS, port=PORT_CACHE_REDIS, db=0)

# PosResp msg fmt.
POS_RESP_FULL="""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE PosRes SYSTEM "PosRes.dtd">
<PosRes>
        <Result ErrCode="%s" ErrDesc="%s"/>
        <Coord lat="%s" lon="%s" h="0.0"/>
        <ErrRange val="%s"/>
        <PosLevel val="%s" />
        <Area code="%s" addr="%s"/>
</PosRes>"""
POS_RESP_PT="""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE PosRes SYSTEM "PosRes.dtd">
<PosRes>
        <Result ErrCode="%s" ErrDesc="%s"/>
        <Coord lat="%s" lon="%s" h="0.0"/>
        <ErrRange val="%s"/>
        <PosLevel val="%s" />
</PosRes>"""
POS_RESP_AREA="""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE PosRes SYSTEM "PosRes.dtd">
<PosRes>
        <Result ErrCode="%s" ErrDesc="%s"/>
        <PosLevel val="%s" />
        <Area code="%s" addr="%s"/>
</PosRes>"""
XHTML_IMT = "application/xhtml+xml"

# FPP-WPP rawdata sync related.
ftpcfgs = { 
  'fpp_neu_ln': {
       'user' : 'fpp',
     'passwd' : '123fpp!@#',
          'ip': '10.64.74.33',
        'port': 21,
        'path': 'fpp/data_sync/wpp',
     'timeout': 20,
    'localdir': '/opt/projs/cmri/wpp/src/wpp/dat/sync'},
'fpp_neu_cmri': {
       'user' : 'fpp',
     'passwd' : 'fpp',
          'ip': '192.168.109.58',
        'port': 21,
        'path': 'fpp/data_sync/wpp',
     'timeout': 20,
    'localdir': '/opt/wpp/src/wpp/dat/sync'},
  'local': {
       'user' : 'alexy',
     'passwd' : 'yan714257',
          'ip': 'localhost',
        'port': 21,
        'path': 'tmp/wpp/ftp',
     'timeout': 10,
    'localdir': '/home/alexy/tmp/wpp/local'},
}
FTPCFG = ftpcfgs['fpp_neu_cmri']
mailcfg = {
      'from' : 'xiaotian.yan@gmail.com',
       'to'  : '13811310350@139.com',
    'userpwd': ('xiaotian.yan','yan714257'),
}
errmsg = { 'db' : """
TABLE: [%s]
OPERATION: [%s]
DETAILS: %s

--
WPP@%s
%s""",
}
# DB related configuration.
DB_CFG = {
    'wpp_cmri': {
        'online' : '192.168.109.54',
        'offline' : ( '192.168.109.54', ),
        'upload' : ( '192.168.109.54', ),
    },
    'wpp_local': {
        'online' : 'local_pg',
        'offline' : ( 'local_pg', ),
        'upload' : ( 'local_pg', ),
    },
    'wpp_cmri_indoor': {
        'online' : 'cmri_pg_indoor',
        'offline' : ( 'cmri_pg_indoor', ),
        'upload' : ( 'cmri_pg_indoor', ),
    },
    'wpp_local_indoor': {
        'online' : 'local_pg_indoor',
        'offline' : ( 'local_pg_indoor', ),
        'upload' : ( 'local_pg_indoor', ),
    },
}
#DB = DB_CFG['wpp_local']
DB = DB_CFG['wpp_cmri']
DB_ONLINE  = DB['online']
DB_OFFLINE = DB['offline']
DB_UPLOAD  = DB['upload']
# dsn config.
dsn_local_pg = "host=localhost dbname=wppdb user=wpp password=wpp port=5432"
#dsn_local_pg_indoor = "host=localhost dbname=wppdb_indoor user=wpp password=wpp port=5432"
#dsn_cmri_pg_indoor = "host=192.168.109.54 dbname=wppdb_indoor user=wpp password=wpp port=5432"
dsn_cmri_pg = "host=192.168.109.54 dbname=wppdb user=wpp password=wpp port=5432"
#dsn_vance_pg = "host=192.168.109.49 dbname=wppdb user=mwlan password=mwlan_pw port=5432"
#dsn_local_ora = "yxt/yxt@localhost:1521/XE"
#dsn_vance_ora = "mwlan/mwlan_pw@192.168.35.202/wlandb"
#dsn_vance_pg_mic = "host=192.168.19.132 dbname=wpp user=mwlan password=mwlan_pw port=5432"
#dbtype_ora = 'oracle' 
#dbtype_my  = 'mysql'
dbtype_pg  = 'postgresql'
dbsvrs = {
          '192.168.109.54':{
            'dsn':dsn_cmri_pg,
            'dbtype':dbtype_pg,
           },
          'local_pg':{
            'dsn':dsn_local_pg,
            'dbtype':dbtype_pg,
           },
          #'cmri_pg_indoor':{
          #  'dsn':dsn_cmri_pg_indoor,
          #  'dbtype':dbtype_pg,
          # },
          #'local_pg_indoor':{
          #  'dsn':dsn_local_pg_indoor,
          #  'dbtype':dbtype_pg,
          # },
          #'192.168.109.49':{
          #  'dsn':dsn_vance_pg,
          #  'dbtype':dbtype_pg,
          # },
          #'local_ora':{
          #  'dsn':dsn_local_ora,
          #  'dbtype':dbtype_ora,
          # },
        }
#db_config_my = {
#            'hostname' : 'localhost',
#            'username' : 'pos',
#            'password' : 'pos',
#              'dbname' : 'wlanpos' }
## SQL table related data structs.
#wpp_tables_my = { 'cidaps' : 'cidaps', 
#                    'cfps' : 'cfps'}
##wpp_tables_my = ( 'cidaps', 'cfps' )
#tbl_field_my = { 'cidaps':'(cid, keyaps, seq)',
#                   'cfps':'(cid, lat, lon, height, rsss, cfps_time)' }
#tbl_forms_my = {'cidaps':""" (
#                     cid SMALLINT NOT NULL, 
#                  keyaps VARCHAR(1024),
#                     seq SMALLINT,
#                   INDEX icid (cid)
#                )""", 
#                'cfps':""" (
#                     cid SMALLINT NOT NULL,
#                     lat DOUBLE(9,6),
#                     lon DOUBLE(9,6),
#                  height DOUBLE(5,1),
#                    rsss VARCHAR(255),
#               cfps_time VARCHAR(20),
#                   INDEX icid (cid)
#                )""" }
# { table_name: table_instance }
wpp_tables = { 'wpp_clusteridaps':'wpp_clusteridaps',
                       'wpp_cfps':'wpp_cfps',
                 'wpp_uprecsinfo':'wpp_uprecsinfo',
                  'wpp_uprecsver':'wpp_uprecsver',
                     'wpp_celloc':'wpp_celloc',
                   'wpp_cellarea':'wpp_cellarea',
               'wpp_uprecs_noloc':'wpp_uprecs_noloc' }
# NOTE: tbl_fields dont contain PRIMAY key or SERIAL columns, like *id* in wpp_uprecsinfo.
tbl_field = { 'wpp_clusteridaps':('clusterid', 'keyaps', 'seq'),
                      'wpp_cfps':('clusterid', 'lat', 'lon', 'height', 'rsss', 'cfps_time'),
                'wpp_uprecsinfo':('spid','servid','time','imsi','imei','useragent',
                                  'mcc','mnc','lac','cellid','cellrss',
                                  'lat','lon','height','wlanidentifier','wlanmatcher',
                                  'ver_uprecs', 'area_ok', 'area_try'),
              'wpp_uprecs_noloc':('spid','servid','time','imsi','imei','useragent',
                                  'mcc','mnc','lac','cellid','cellrss',
                                  'lat','lon','height','wlanidentifier','wlanmatcher',
                                  'ver_uprecs'),
                    'wpp_celloc':('laccid', 'lat', 'lon', 'h', 'ee'),
                  'wpp_cellarea':('laccid', 'areacode', 'areaname'),
                        'tsttbl':('clusterid', 'keyaps', 'seq') }
tbl_idx =   { 'wpp_clusteridaps':('clusterid','keyaps'), #{table_name:{'field_name'}}
                      'wpp_cfps':('clusterid',),
                'wpp_uprecsinfo':('ver_uprecs','area_ok'),
              'wpp_uprecs_noloc':('ver_uprecs',),
                    'wpp_celloc':('laccid',),
                  'wpp_cellarea':('laccid',),
                 'wpp_uprecsver':(),
                        'tsttbl':('clusterid',)}
tbl_files = { 'wpp_clusteridaps':'test/tbl/cidaps.tbl', 
                      'wpp_cfps':'test/tbl/cfprints.tbl',
                'wpp_uprecsinfo':'test/tbl/uprecs.tbl',
              'wpp_uprecs_noloc':'test/tbl/uprecs_noloc.tbl',
                 'wpp_uprecsver':'test/tbl/uprecsver.tbl',
                        'cidaps':'test/tbl/cidaps.tbl',
                          'cfps':'test/tbl/cfprints.tbl',
                    'wpp_celloc':'test/tbl/celloc.tbl',
                  'wpp_cellarea':'test/tbl/cellarea.tbl',
                        'tsttbl':'test/tbl/tsttbl.tbl' }
tbl_forms = { 
              #'oracle':{
              #  'wpp_clusteridaps':""" (  
              #       clusterid INT NOT NULL, 
              #          keyaps VARCHAR2(71) NOT NULL,
              #             seq INT NOT NULL)""", 
              #  'wpp_cfps':""" (  
              #       clusterid INT NOT NULL,
              #             lat NUMBER(9,6) NOT NULL,
              #             lon NUMBER(9,6) NOT NULL,
              #          height NUMBER(5,1) DEFAULT 0,
              #            rsss VARCHAR2(100) NOT NULL,
              #       cfps_time VARCHAR2(20))""",
              #  'wpp_uprecsinfo':""" (  
              #              id INT PRIMARY KEY,	
              #            spid INT,
              #          servid INT,
              #            time VARCHAR(20),
              #            imsi VARCHAR(20),
              #            imei VARCHAR(20),
              #       useragent VARCHAR(300),
              #             mcc INT,
              #             mnc INT,
              #             lac INT,
              #          cellid INT,
              #         cellrss VARCHAR(5),
              #             lat NUMERIC(9,6),
              #             lon NUMERIC(9,6),
              #          height NUMERIC(5,1),
              #  wlanidentifier VARCHAR(1024),
              #     wlanmatcher VARCHAR(255))""",
              #  'tsttbl':"""(
              #       clusterid INT, 
              #          keyaps VARCHAR2(71) NOT NULL,
              #             seq INT NOT NULL)""" },
              'postgresql':{
                'wpp_clusteridaps':"""(
                     clusterid INT NOT NULL, 
                        keyaps VARCHAR(360) NOT NULL,
                           seq INT NOT NULL)""", 
                'wpp_cfps':""" (
                     clusterid INT NOT NULL,
                           lat NUMERIC(9,6) NOT NULL,
                           lon NUMERIC(9,6) NOT NULL,
                        height NUMERIC(5,1) DEFAULT 0,
                          rsss VARCHAR(100) NOT NULL,
                     cfps_time VARCHAR(20))""",
                'wpp_cellarea':""" (
                        laccid VARCHAR(30) NOT NULL,
                      areacode VARCHAR(10) NOT NULL,
                      areaname VARCHAR(50) NOT NULL)""",
                'wpp_celloc':""" (
                        laccid VARCHAR(30) NOT NULL,
                           lat NUMERIC(9,6) NOT NULL DEFAULT 0,
                           lon NUMERIC(9,6) NOT NULL DEFAULT 0,
                             h NUMERIC(5,1) DEFAULT 0,
                            ee NUMERIC(5,1) DEFAULT 0)""",
                'wpp_uprecsver':""" (
                    ver_uprecs INT DEFAULT 0)""",
                'wpp_uprecsinfo':""" (
                          spid INT,
                        servid INT,
                          time VARCHAR(20),
                          imsi VARCHAR(20),
                          imei VARCHAR(20),
                     useragent VARCHAR(300),
                           mcc INT DEFAULT 0,
                           mnc INT DEFAULT 0,
                           lac INT DEFAULT 0,
                        cellid INT DEFAULT 0,
                       cellrss VARCHAR(5),
                           lat NUMERIC(9,6) DEFAULT 0,
                           lon NUMERIC(9,6) DEFAULT 0,
                        height NUMERIC(5,1) DEFAULT 0,
                wlanidentifier VARCHAR(1024),
                   wlanmatcher VARCHAR(255),
                    ver_uprecs INT DEFAULT 0),
                       area_ok SMALLINT DEFAULT 0),
                      area_try INT DEFAULT 0)""",
                'wpp_uprecs_noloc':""" (
                          spid INT,
                        servid INT,
                          time VARCHAR(20),
                          imsi VARCHAR(20),
                          imei VARCHAR(20),
                     useragent VARCHAR(300),
                           mcc INT DEFAULT 0,
                           mnc INT DEFAULT 0,
                           lac INT DEFAULT 0,
                        cellid INT DEFAULT 0,
                       cellrss VARCHAR(5),
                           lat NUMERIC(9,6) DEFAULT 0,
                           lon NUMERIC(9,6) DEFAULT 0,
                        height NUMERIC(5,1) DEFAULT 0,
                wlanidentifier VARCHAR(1024),
                   wlanmatcher VARCHAR(255),
                    ver_uprecs INT DEFAULT 0)""",
                'tsttbl':"""(
                     clusterid INT, 
                        keyaps VARCHAR2(71) NOT NULL,
                           seq INT NOT NULL)""" }}
# SQL statements.
sqls = { 'SQL_SELECT' : "SELECT %s FROM %s",
         'SQL_UPDATE' : "UPDATE %s SET %s = %s",
         'SQL_DELETE' : "DELETE FROM %s WHERE %s",
         'SQL_DROPTB' : "DROP TABLE %s PURGE",
      'SQL_DROPTB_IE' : "DROP TABLE IF EXISTS %s",
         'SQL_INSERT' : "INSERT INTO %s %s VALUES %s",
  'SQL_INSERT_SELECT' : "INSERT INTO %s SELECT %s FROM %s",
        'SQL_TRUNCTB' : "TRUNCATE TABLE %s",
        'SQL_DROP_MY' : "DROP TABLE IF EXISTS %s",
       'SQL_DROP_IDX' : "DROP INDEX %s",
    'SQL_DROP_IDX_IE' : "DROP INDEX IF EXISTS %s",
       'SQL_CREATETB' : "CREATE TABLE %s %s",
      'SQL_CREATEIDX' : "CREATE INDEX %s ON %s(%s)",
     'SQL_CREATEUIDX' : "CREATE UNIQUE INDEX %s ON %s(%s)",
    'SQL_CREATETB_MY' : "CREATE TABLE IF NOT EXISTS %s %s",
       'SQL_CSVIN_MY' : """
                        LOAD DATA LOCAL INFILE "%s" INTO TABLE %s 
                        FIELDS TERMINATED BY ',' 
                        LINES TERMINATED BY '\\n' 
                        %s""" }

# Test input csv file
TESTFILE = os.path.dirname(__file__) + '/../dat/test.csv'
# Text colors
termtxtcolors = {
        'red':'\033[91m%s\033[0m',
      'green':'\033[92m%s\033[0m',
     'yellow':'\033[93m%s\033[0m',
       'blue':'\033[94m%s\033[0m',
     'purple':'\033[95m%s\033[0m'
}
# String length of 179 and 149 chars are used for each intersection set to have 
# at most INTERSET APs, which should be enough for classification, very ugly though.
#dt_rmp_nocluster = {'names':('spid','lat','lon','macs','rsss'), 
#                  'formats':('i4','f4','f4','S179','S149')}
WLAN_FAKE = {
        1: #home
            [ ['00:25:86:23:A4:48', '-86'], ['00:24:01:FE:0F:20', '-90'], 
              ['00:0B:6B:3C:75:34', '-89'] ],
        2: #home-only 1 visible
            [ ['00:0B:6B:3C:75:34', '-89'] ],
        3: #cmri-only 1 visible
            [ ['00:15:70:9E:91:60', '-53'] ],
        4: #cmri-fail
            [ ['00:15:70:9F:7D:88', '-82'], ['00:15:70:9F:7D:89', '-77'],
              ['00:15:70:9F:7D:8A', '-77'], ['00:23:89:3C:BD:F2', '-81'],
              ['00:11:B5:FD:8B:6D', '-81'], ['00:23:89:3C:BE:10', '-70'],
              ['00:23:89:3C:BE:11', '-70'], ['00:23:89:3C:BE:13', '-71'],
              ['00:15:70:9E:91:62', '-72'], ['00:15:70:9E:91:60', '-49'],
              ['00:23:89:3C:BD:32', '-75'], ['00:15:70:9E:91:61', '-50'],
              ['00:23:89:3C:BE:12', '-75'], ['00:23:89:3C:BD:33', '-76'],
              ['00:14:BF:1B:A5:48', '-79'], ['00:15:70:9E:6C:6D', '-68'],
              ['00:15:70:9E:6C:6C', '-68'], ['00:15:70:9E:6C:6E', '-68'],
              ['00:23:89:3C:BD:30', '-75'], ['00:23:89:3C:BD:31', '-75'],
              ['00:23:89:3C:BC:90', '-79'], ['00:23:89:3C:BC:93', '-75'],
              ['00:11:B5:FE:8B:6D', '-88'], ['00:23:89:3C:BC:91', '-80'],
              ['00:23:89:3C:BC:92', '-81'], ['00:23:89:3C:BD:F1', '-80']],
        5: #cmri-ok-part
            [ ['00:15:70:9F:7D:8A', '-76'], ['00:15:70:9F:7D:88', '-77'],
              ['00:15:70:9F:7D:89', '-80'], ['00:11:B5:FD:8B:6D', '-79'],
              ['00:23:89:3C:BC:90', '-75'], ['00:23:89:3C:BC:91', '-76'],
              ['00:23:89:3C:BC:92', '-76'], ['00:23:89:3C:BC:93', '-75'],
              ['00:23:89:3C:BE:12', '-73'], ['00:23:89:3C:BE:10', '-75'],
              ['00:23:89:3C:BE:11', '-69'], ['00:15:70:9E:91:61', '-63'],
              ['00:23:89:3C:BE:13', '-71'], ['00:15:70:9E:91:62', '-61'],
              ['00:15:70:9E:91:60', '-62'], ['00:14:BF:1B:A5:48', '-81'],
              ['00:23:89:3C:BD:33', '-73'], ['00:15:70:9E:6C:6C', '-67'],
              ['00:15:70:9E:6C:6D', '-68'], ['00:15:70:9E:6C:6E', '-67']],
        6: #cmri-ok-full
            [ ['00:11:B5:FD:8B:6D', '-69'], ['00:15:70:9E:91:60', '-52'], 
              ['00:15:70:9E:91:61', '-53'], ['00:15:70:9F:73:64', '-78'], 
              ['00:15:70:9F:73:66', '-75'], ['00:15:70:9E:91:62', '-55'],
              ['00:23:89:3C:BE:10', '-74'], ['00:23:89:3C:BE:11', '-78'], 
              ['00:23:89:3C:BE:12', '-78'], ['00:11:B5:FE:8B:6D', '-80'], 
              ['00:15:70:9E:6C:6C', '-65'], ['00:15:70:9E:6C:6D', '-60'],
              ['00:15:70:9E:6C:6E', '-70'], ['00:15:70:9F:76:E0', '-81'], 
              ['00:15:70:9F:7D:88', '-76'], ['00:15:70:9F:73:65', '-76'], 
              ['00:23:89:3C:BD:32', '-75'], ['00:23:89:3C:BD:30', '-78'],
              ['02:1F:3B:00:01:52', '-76'] ],
        7: #cmri-square-fail
            [ ['00:16:16:1F:14:E0', '-49'], ['00:16:16:1E:EB:60', '-78'] ],
        8: #hq-fail
            [ ['00:60:B3:C9:61:27', '-63'], ['00:16:16:1E:B9:80', '-64'],
              ['00:1A:70:FB:B8:7F', '-65'], ['00:17:7B:0F:16:D9', '-66'] ],
        9: #hq-fail
            [ ['00:60:B3:C9:61:27', '-61'], ['00:1B:54:25:86:40', '-64'],
              ['00:17:7B:0F:16:D8', '-66'], ['00:17:7B:0F:16:D9', '-65'] ],
        10:#hq-ok
            [ ['00:60:B3:C9:61:27', '-64'], ['00:1E:E3:E0:69:40', '-64'],
              ['00:17:7B:0F:16:D8', '-66'], ['00:16:16:1E:B9:80', '-65'] ],
        11:#hq-fail
            [ ['00:60:B3:C9:61:27', '-66'], ['00:16:16:1E:82:20', '-67'],
              ['00:17:7B:0F:16:D8', '-67'], ['00:16:16:1F:24:A0', '-67'] ],
        12:#hq-fail
            [ ['00:60:B3:C9:61:27', '-63'], ['00:16:16:1E:B9:80', '-66'],
              ['00:17:7B:0F:16:D8', '-66'], ['00:16:16:1E:78:C0', '-69'] ],
        13:#hq-fail
            [ ['00:60:B3:C9:61:27', '-65'], ['00:17:7B:0F:16:D9', '-67'],
              ['00:17:7B:0F:16:DA', '-67'], ['00:1B:53:6C:E7:B0', '-67'] ],
        14:#hq-fail
            [ ['00:60:B3:C9:61:27', '-64'], ['00:17:7B:0F:16:D9', '-69'],
              ['00:16:16:1E:B9:80', '-65'], ['00:16:16:1F:30:60', '-68'] ],
        15:#hq-fail
            [ ['00:60:B3:C9:61:27', '-65'], ['00:17:7B:0F:16:D9', '-67'],
              ['00:1B:54:25:86:40', '-64'], ['00:16:16:1F:30:60', '-66'] ],
        16:#hq-fail
            [ ['00:60:B3:C9:61:27', '-65'], ['00:17:7B:0F:16:D9', '-66'],
              ['00:1B:54:25:86:40', '-66'], ['00:17:7B:0F:16:D8', '-66'] ],
        17:#hq-fail-dknn_0_and_1
            [ ['00:1E:E3:E0:69:40', '-66'], ['00:1D:7E:51:E0:8D', '-69'],
              ['00:16:16:1E:82:20', '-69'], ['00:17:7B:0F:16:D8', '-69'] ],
        18:#hq-square-interpolated-between-1313-and-902
            [ ['00:23:89:5F:D8:A1', '-71'], ['00:15:70:D0:52:60', '-71'],
              ['00:15:70:D0:52:61', '-73'], ['00:23:89:5C:9E:D0', '-73'] ],
        19:#hq-square
            [ ['00:17:7B:FC:34:70', '-60'], ['00:15:70:D0:52:62', '-65'],
              ['00:23:89:3C:BD:12', '-67'], ['00:15:70:D0:52:60', '-67'] ],
        20:#hq-square
            [ ['00:17:7B:FC:34:70', '-61'], ['00:15:70:D0:52:62', '-68'],
              ['00:15:70:D0:52:61', '-68'], ['00:23:89:3C:BD:13', '-69'] ],
        21:#bigerr-wpp: 905.11, signal too weak!!
            [ ['00:19:E0:E3:85:D0','-92'] ],
        22:#bigerr-wpp: 162.56
            [ ['00:17:7B:0F:85:F0','-68'] ],
        23:#issue 24: mismatch between queried macs/rsss.
            [ ['00:17:7B:0F:0F:08', '-73'], ['00:1F:A4:05:AF:3E', '-78'],
              ['00:24:01:25:0B:CC', '-79'], ['74:EA:3A:4C:B8:58', '-81'] ],
        24:#issue 25: K nearest FPs, which should be K nearest distances.
            [ ['52:C3:17:AE:71:51', '-91'] ],
        25:
            [ ['00:21:91:1D:C0:D4', '-90'], ['00:25:86:4D:B4:C4', '-90'] ],
        26:
            [ ['00:17:7B:0F:0F:58', '-85'], ['00:27:19:52:B5:20', '-83'] ],
        27:
            [ ['00:21:91:1D:C1:06', '-84'] ],
        28: # nan
            [ ['00:23:69:D8:B0:80', '-81'] ],
        29: # nan
            [ ['00:21:27:50:99:AC', '-82'] ],
        30: # nan
            [ ['00:27:19:64:DE:78', '-85'] ],
        31: # 
            [ ['00:0F:3D:0B:51:28', '-89'], ['00:1F:A3:B6:7B:C0', '-80'],
              ['00:21:27:50:99:AC', '-77'], ['00:27:19:9E:48:A0', '-78'],
              ['D8:5D:4C:63:FA:A6', '-88'] ],
        32: # bigerr 135.20
            [ ['00:21:91:1D:C1:06', '-84'] ],
        33: # bigerr 1581.43
            [ ['00:b0:0c:4b:75:c0', '-82'], ['00:25:86:37:19:2e', '-84'],
              ['00:90:4c:7e:00:64', '-85'], ['00:19:e0:e0:3f:7c', '-85'] ],
        34: # crossover of bigerr 1581.43
            [ ['00:b0:0c:4b:75:c0', '-82'], ['00:25:86:37:19:2e', '-84'],
              ['00:90:4c:7e:00:64', '-85'], ['00:17:7b:fc:34:28', '-87'] ],
        35: # bigerr 791
            [ ['00:17:7b:0f:0f:58', '-78'], ['00:b0:0c:0f:3e:98', '-86'],
              ['00:17:7b:0f:7a:b0', '-90'], ['1c:af:f7:a7:ba:b4', '-91'] ],
        36: # Indoor: cluster #6, full match, 3 fps.
            [ ['5C:63:BF:62:6D:32', '-28'], ['54:E6:FC:1F:DD:02', '-66'],
              ['5C:63:BF:A8:D7:56', '-70'], ['F4:EC:38:22:5F:7E', '-81'] ],
        37: # Indoor: cluster #8, full match, 1 fps.
            [ ['5C:63:BF:62:6D:32', '-28'], ['54:E6:FC:1F:DD:02', '-66'],
              ['5C:63:BF:A8:D7:56', '-70'], ['B0:48:7A:66:8B:6A', '-77'] ],
        38: # Indoor: cluster #2, #6, #8, part match(3), 34 fps.
            [ ['5C:63:BF:62:6D:32', '-28'], ['54:E6:FC:1F:DD:02', '-66'],
              ['5C:63:BF:A8:D7:56', '-70'], ],
        39: # Indoor
            [ ['00:11:b5:fd:8e:f6', '-28'], ['38:83:45:6a:55:2c', '-66'],
              ['d2:73:56:c0:ea:7d', '-70'], ],

            
}
icon_types = { 'on': [ '"encrypton"',  '/kml/icons/encrypton.png'],
              'off': [ '"encryptoff"', '/kml/icons/encryptoff.png'],
           'reddot': [ '"reddot"',     '/kml/icons/reddot.png'],
          'bluedot': [ '"bluedot"',    '/kml/icons/bluedot.png'],
        'yellowdot': [ '"yellowdot"',  '/kml/icons/yellowdot.png'],
             'wifi': [ '"wifi"',       '/kml/icons/wifi.png'],
        'dotshadow': [ '"dotshadow"',  '/kml/icons/dotshadow.png'],
}

#props_jpg = {'term':'jpeg', # MUST be recognized by Gnuplot.
#         'outfname':'cdf.jpg',
#             'font':'"/usr/share/fonts/truetype/arphic/gbsn00lp.ttf, 14"',
#             'size':'', # default: 1,1
#            'title':'误差累积函数',
#           'xlabel':'误差/米',
#           'ylabel':'概率',
#           'legend':'',
#              'key':'right bottom',
#           'xrange':[0,100],
#           'yrange':[0,1],
#            'xtics':'nomirror 10',
#            'ytics':'nomirror .05',
#             'grid':'x y', # default: off
#           'border':3,
#             'with':'lp pt 3 lc 1'}
#props_mp = { 'term':'mp latex', # MUST be recognized by Gnuplot.
#         'outfname':'cdf.mp',
#             'font':'"Romans" 7',
#             'size':'.8, .8', # default: 1,1
#            'title':'CDF',
#           'xlabel':'error/m',
#           'ylabel':'probability',
#           'legend':'',
#              'key':'right bottom',
#           'xrange':[0,100],
#           'yrange':[0,1],
#            'xtics':'nomirror 10',
#            'ytics':'nomirror .05',
#             'grid':'x y', # default: off
#           'border':3,
#             'with':'lp pt 4'}
