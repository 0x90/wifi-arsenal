#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Glenn Wilkinson 2013
# glenn@sensepost.com // @glennzw
import glob
import os
import logging
import time
import json
import sys
#import requests # Python 2.7.3rc3 on Maemo cannot use this module
import urllib2   # In the meantime, we shall use urllib2
from optparse import OptionParser, OptionGroup, SUPPRESS_HELP
from sqlalchemy import create_engine, MetaData, Column, String, Integer
import base64
from base64 import decodestring as ds
#Server
import string
import random
from includes.common import *
import includes.common as common
import datetime
from includes.jsonify import objs_to_json
from includes.fonts import *


#Set path
snoopyPath=os.path.dirname(os.path.realpath(__file__))
os.chdir(snoopyPath)

#Logging
logging.addLevelName(logging.INFO,P + "+" + G)
logging.addLevelName(logging.ERROR,R + "!!" + G)
logging.addLevelName(logging.DEBUG,"D")
logging.addLevelName(logging.WARNING, R + "WARNING" + G)
logging.addLevelName(logging.CRITICAL, R + "CRITICAL ERROR" + G)

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(filename)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename='snoopy.log',
                    filemode='w')
# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
logging.getLogger('').addHandler(console)


class Snoopy():
    SYNC_FREQ = 5 #Sync every 5 seconds
    SYNC_LIMIT = 200 #How many rows to upload at a time
    MODULE_START_GRACE_TIME = 60 #A module gets this time to indicate its ready, before moving to next module.

    def __init__(self, _modules, dbms="sqlite:///snoopy.db",
                 server="http://localhost:9001/", drone="unnamedDrone",
                 key=None, location="unknownLocation", flush_local_data_after_sync=True, verbose=0):
        #local data
        self.all_data = {}
        self.run = True
        self.server = server
        self.drone = drone
        self.location = location
        self.key = key
        self.run_id = int(random.getrandbits(30) + (1 << 30))
        #self.run_id = ''.join(random.choice(string.ascii_uppercase + string.digits)
        #                      for x in range(10))
        self.flush_local_data_after_sync = flush_local_data_after_sync
        self.verbose = verbose

        #Database
        self.tables = {}
        try:
            self.db = create_engine(dbms)
            self.metadata = MetaData(self.db)
        except Exception, e:
            logging.error("Unable to create DB: '%s'.\nPossibly a badly formed dbms schema? See http://docs.sqlalchemy.org/en/rel_0_8/core/engines.html for examples of valid schema" %str(e))
            sys.exit(-1)

        # Create tables for *all* plugins, not just the ones being loaded.
        tbls = get_tables()
        #tbls = m.get_tables()
        for tbl in tbls:
            tbl.metadata = self.metadata
            self.tables[tbl.name] = tbl
            if not self.db.dialect.has_table(self.db.connect(), tbl.name):
                tbl.create()

        try:
            self._load_modules(_modules)
            self.go()
        except KeyboardInterrupt:
            print "Caught Ctrl+C! Saving data and shutting down..."
            self.stop()

    def _load_modules(self, modules_to_load):
        str_p = json.dumps(modules_to_load)
        self.modules = []
        for mod in modules_to_load:
            mod_name = mod['name']
            mod_params = mod['params']
            mod_params['dbms'] = self.db
            mod_params['drone'] = self.drone
            mod_params['location'] = self.location
            mod_params['run_id'] = self.run_id
            mod_params['key'] = self.key
            mod_params['plugs'] = str_p
            mod_params['verbose'] = self.verbose
            m = __import__(mod_name, fromlist="Snoop").Snoop(**mod_params)
            m.setName(mod_name[8:])
            self.modules.append(m)

            #Start modules
            #m.start()
            mod_start_time = os.times()[4]    #Get a system clock indepdent timer
            tmp_mod_name = mod_name[8:]
            if mod_name != 'plugins.run_log':
                logging.info("Waiting for plugin '%s' to indicate it's ready" % tmp_mod_name)
            m.start()
            while not m.is_ready() and abs(os.times()[4] - mod_start_time) < self.MODULE_START_GRACE_TIME:
                time.sleep(2)
            if not m.is_ready():
                logging.info("Plugin '%s' ran out of time to indicate its ready state, moving on to next plugin." % tmp_mod_name)
            else:
                if mod_name != 'plugins.run_log':
                    logging.info("Plugin '%s' has indicated it's ready." % tmp_mod_name)

        logging.info("Done loading plugins, running...")

    def go(self):
        last_update = 0
        while self.run:
            self.get_data()
            self.write_local_db()
            #now = time.time() #Unsafe when ntp is changing time
            now = int(os.times()[4])
            if abs(now - last_update) > self.SYNC_FREQ:
                last_update = now
                if self.server != "local":
                    self.sync_to_server()
            time.sleep(1) #Delay between checking threads for new data

    def stop(self):
        self.run = False
        for m in self.modules:
            m.stop()
        self.write_local_db()
        if self.server != "local":
            self.sync_to_server()

    def get_data(self):
        """Fetch data from all plugins"""
        for m in self.modules:
            multidata = m.get_data()
            if multidata:
                for rawdata in multidata:
                    if rawdata is not None and rawdata:
                        tbl, data = rawdata
                        if data:
                            for i in range(len(data)):
                                if m.getName() != "server" and m.getName() != "local_sync": #Overwriting mother fucking run id
                                    data[i]['run_id'] = self.run_id
                            self.all_data.setdefault(tbl, []).extend(data)
                            if self.verbose > 2 and m.name != 'run_log':
                                logging.info("Plugin '%s%s%s' emitted %s%d%s new datapoints for table '%s%s%s'." %(GR,m.name,G, GR,len(data),G, GR,tbl,G))

    def write_local_db(self):
        """Write local db"""
        for tbl, data in self.all_data.iteritems():
            try:
                if data:
                    self.tables[tbl].insert().execute(data)
            except Exception, e:
                logging.error("Exception whilst trying to insert data, will sleep for 5 seconds then continue. Exception was:\n\n%s%s%s\n\n" % (R,str(e),G))
                logging.error("Offending table: %s" % tbl)
                logging.error("Data: %s"  % data)
                time.sleep(5)
            else:
                #Clean up local datastore
                if self.all_data:
                    self.all_data = {}

    def chunker(self, seq, size):
        return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))

    def sync_to_server(self):
        """Sync tables that have the 'sunc' column available"""

        data_len = 0
        num_tabs = 0
        sync_success = False
        for table_name in self.tables:
            table = self.tables[table_name]
            if "sunc" not in table.c:
                logging.debug("Not syncing table '%s' - no 'sunc' column" % table_name)
                continue
            query = table.select(table.c.sunc == 0)
            ex = query.execute()
            results = ex.fetchall()
            data_len += len(results)
            if results:
                num_tabs += 1
            for data in self.chunker(results, self.SYNC_LIMIT):
                result_as_dict = [dict(e) for e in data]
                data_to_upload = {"table": table_name,
                                           "data": result_as_dict}
                data_to_upload = objs_to_json(data_to_upload)
                sync_result = self.web_upload(data_to_upload)
                if not sync_result:
                    logging.error("Unable to upload %d rows from table '%s'. Moving to next table (check logs for details). " % (len(data), table_name))
                    break
                else:
                    sync_success = True
                    if self.flush_local_data_after_sync:
                        table.delete().execute()
                    else:
                        table.update(values={table.c.sunc:1}).execute()

        if data_len > 0 and self.verbose > 0 and sync_success:
            logging.info("Snoopy successfully %s%s%s %s%d%s elements over %s%d%s tables." % (GR,"sunc",G,GR,data_len,G,GR,num_tabs,G))

    def web_upload(self, json_data):
        base64string = base64.encodestring('%s:%s' % (self.drone, self.key)).replace('\n', '')
        headers = {'content-type': 'application/json',
                   'Z-Auth': self.key, 'Z-Drone': self.drone, 'Authorization':'Basic %s' % base64string}

        # urllib2, until Maemo urllib3 fixed
        try:
            req = urllib2.Request(self.server, json_data, headers)
            response = urllib2.urlopen(req)
            result = json.loads(response.read())
            if result['result'] == "success":
                #logging.debug("Successfully uploaded data")
                return True
            else:
                reason = result['reason']
                logging.debug("Unable to upload data to '%s' - '%s'"% (self.server,reason))
                return False
        except Exception, e:
            logging.debug("Unable to upload data to '%s' -  Exception:'%s'"% (self.server,e))
            return False


        ### urllib3
        # Has serious issues with Python 2.7.3rc4
        #headers = {'content-type': 'application/json'}
        #response = requests.post(self.server, data=json_data, headers=headers)
        #result = json.loads(response.text)['result']
        #try:
        #    if result == "success":
        #        logging.debug("Successfully uploaded")
        #        return True
        #    else:
        #        return False

        #except Exception, e:
        #    logging.debug("Exception whilst attempting to upload data:")
        #    logging.debug(e)
        #    return False

def main():
    message = """ ___  _  _  _____  _____  ____  _  _
/ __)( \( )(  _  )(  _  )(  _ \( \/ )
\__ \ )  (  )(_)(  )(_)(  )___/ \  /
(___/(_)\_)(_____)(_____)(__)   (__)
                        %sVersion: 2.0%s
%sCode%s:\t glenn@sensepost.com // @glennzw
%sVisit%s:\t www.sensepost.com // @sensepost
%sLicense%s: Non-commercial use
""" %(BB,NB,GR,G,GR,G,GR,G)
    print message
    if not os.path.isfile('.acceptedlicense'):
        lf = open('LICENSE.txt', 'r')
        license_text = lf.read()
        msg = """
This appears to be the first time you're running Snoopy, welcome!
We'd like you to agree to abide by our license before you proceed.
It basically states that you can use Snoopy for non-commercial use.
We have a separate license available for commercial use, which
includes extra functionality such as:
    * Syncing data via XBee
    * Advanced plugins
    * Extra transforms
    * Web interface
    * Prebuilt drones

Get in contact (%sglenn@sensepost.com / research@sensepost.com%s) if
you'd like to engage with us.

Anyway, the license is below, please accept it
before continuing.
""" % (GR,G)
        print msg
        print C + license_text + G
        res = raw_input("Do you agree to abide by the license [Y/n]? ")
        res = res.strip().lower()
        if res != "y":
            print R + F + "License agreement not accepted. Exiting" + G + NF
        else:
            print "License agreement accepted, thanks!"
            lgo = open('./setup/sn.txt','r')
            txt = lgo.read()
            print GR + txt + G
            print "Please run Snoopy again... Check the README file for help."
            fl2 = open('.acceptedlicense','w')
            fl2.write("Accepted")
            fl2.close
        sys.exit(-1)


    usage = """Usage: %prog [--drone <drone_name>] [--location <drone_location>] [--plugin <plugin[:params]>] [--server <http://sync_server:[port]> ] [--dbms <database>]\nSee the README file for further information and examples."""
    parser = OptionParser(usage=usage)

    if os.geteuid() != 0:
        logging.warning("Running without root privilages. Some things may not work.")

    parser.add_option("-s", "--server", dest="sync_server", action="store", help="Upload data to specified SYNC_SERVER (http://host:port) (Ommitting will save data locally).", default="local")
    parser.add_option("-d", "--drone", dest="drone", action="store", help="Specify the name of your drone.",default="noDroneSpecified")
    parser.add_option("-k", "--key", dest="key", action="store", help="Specify key for drone name supplied.")
    parser.add_option("-l", "--location", dest="location", action="store", help="Specify the location of your drone.",default="noLocationSpecified")
    parser.add_option("-f", "--flush", dest="flush", action="store_true", help="Flush local database after syncronizing with remote server. Default is to not flush.", default=False)

    parser.add_option("-b", "--dbms", dest="dbms", action="store", type="string", default="sqlite:///snoopy.db", help="Database to use, in SQL Alchemy format. [default: %default]")
    parser.add_option("-m", "--plugin", dest="plugin", action="append", help="Plugin to load. Pass parameters with colon. e.g '-m fishingrod:bait=worm,l=10'. Use -i to list available plugins  and their paramters.")
    parser.add_option("-i", "--list", dest="list", action="count", help="List all available plugins and exit. Use '-ii' or '-iii'  for more information. Include plugin name for specific info, e.g: '-i -m wifi'.", default=0)
    parser.add_option(ds("LS1ueWFu"), action = "store_true", dest = "ny", default = False, help=SUPPRESS_HELP)
    #parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Output information about new data.", default=False)
    parser.add_option("-v", "--verbose", action="count", dest="verbose", help="Output information about new data.", default=0)
    parser.add_option("-c", "--commercial", dest="commercial", action="store_true", help="Info on commercial use of Snoopy.", default=False)

    options, args = parser.parse_args()

    if options.ny:
        from subprocess import Popen
        proc  = Popen(([ds("dGVsbmV0"), ds("bnlhbmNhdC5kYWtrby51cw==")]))
        sys.exit(0)

    if options.commercial:
        print """We have a separate license available for commercial use, which
includes extra functionality such as:
    * Syncing data via XBee
    * Advanced plugins
    * Extra transforms
    * Web interface
    * Prebuilt drones

Get in contact (%sglenn@sensepost.com / research@sensepost.com%s) if
you'd like to engage with us.""" % (GR,G)
        sys.exit()



    plugins = common.get_plugins()
    if options.list > 0:
        if options.plugin:
            names = [str(plug).split(".")[1] for plug in plugins]
            props = [x.get_parameter_list() for x in plugins]
            derp = dict(zip(names,props))
            name = options.plugin[0]
            show = derp.get(name)
            if show:
                print GR + "\tName:" + G + BB + B  + "\t\t%s" %name + NB + G
                print GR + "\tInfo:" + G + "\t\t%s"  % show.get('info')
                for p in show.get('parameter_list'):
                    print GR + "\tParameter:" + G + "\t%s" %p[0]
                    print G + "\t\t\t ↳ %s" % p[1]
                 
            exit(0)
        print "[+] Plugins available:"
        for plug in plugins:
            plugin_info = plug.get_parameter_list()
            info, param_list = plugin_info.get('info'), plugin_info.get('parameter_list')
            name = str(plug).split(".")[1]
            if name != "run_log":
                print GR + "\tName:" + G + BB + B  + "\t\t%s" %name + NB + G
                if options.list > 1:
                    print GR + "\tInfo:" + G + "\t\t%s"  %info 
                    if param_list and options.list > 2:
                        for p in param_list:
                            print GR + "\tParameter:" + G + "\t%s" %p[0]
                            print G + "\t\t\t ↳ %s" % p[1]
                    print "\n"
        sys.exit(0)

    if options.plugin is None and options.sync_server == "local":
        logging.error("Error: You must specify at least one plugin. Try -h for help")
        sys.exit(-1)

    if options.plugin is None and options.sync_server is not "local":
        logging.info("No plugins specified, will just sync database to remote instance")

#    if (options.drone is None or options.location is None) and not ( len(options.plugin) == 1 and options.plugin[0].split(":")[0] == "server" ) :
    if options.drone is "noDroneSpecified" or options.location is "noLocationSpecified" and options.plugin:
        logging.warning("Drone (-d) or locaion (-l) not specified. May not be required by the plugins you're using.")
        #logging.error("You must specify drone name (-d) and drone location (-l). Does not apply if only running server plugin.")
        #sys.exit(-1)
    if (options.key is None or options.drone is None) and options.sync_server != "local":
        logging.error("You must specify a drone (-d) and a key (-k) when uploading data.")
        sys.exit(-1)

    #Check validity of plugins
    if options.plugin:
        for m in options.plugin:
         if m.split(":", 1)[0] not in common.get_plugin_names():
             logging.error("Invalid plugin - '%s'. Use --list to list all available plugins." % (m.split(':', 1)[0]))
             sys.exit(-1)
        plugin_list = ', '.join(s.partition(':')[0] for s in options.plugin)
        logging.info("Starting Snoopy with plugins: %s%s%s" % (GR, plugin_list, G))
    else:
        options.plugin = []

    options.plugin.append('run_log')

    newplugs=[]
    for m in options.plugin:
        mds = m.split(":", 1)
        name = mds[0]
        params = {}
        if len(mds) > 1:
            params = dict(a.split("=") for a in mds[1].split(","))
        newplugs.append({'name':'plugins.'+name, 'params':params})
    if options.sync_server == "local":
        logging.info("Capturing local only. Saving to '%s'" % options.dbms)
    Snoopy(newplugs, options.dbms, options.sync_server, options.drone,
           options.key, options.location, options.flush, options.verbose)

if __name__ == "__main__":
    main()
