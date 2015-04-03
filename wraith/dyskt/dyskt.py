#!/usr/bin/env python

""" dyskt.py: main process captures and collates raw 802.11-2012 traffic

802.11-2012 sensor that collects araw 802.11 frames and gps data for processing
by an external process.
"""

__name__ = 'dyskt'
__license__ = 'GPL v3.0'
__version__ = '0.0.10'
__date__ = 'November 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import os                                       # for path validations
import signal                                   # signal processing
import time                                     # for sleep, timestamps
import logging                                  # log
import logging.config                           # log configuration
import logging.handlers                         # handlers for log
import multiprocessing as mp                    # multiprocessing process, events etc
import argparse as ap                           # reading command line arguments
import ConfigParser                             # reading configuration files
from wraith import dyskt                        # for rev number, author
from wraith.dyskt.rto import RTO                # the rto
from wraith.dyskt.rdoctl import RadioController # Radio object etc
from wraith.radio import channels               # channel specifications
from wraith.radio import iw                     # channel widths and region set/get
from wraith.radio.iwtools import wifaces        # check for interface presents

#### set up log
# have to configure absolute path
GPATH = os.path.dirname(os.path.abspath(__file__))
logpath = os.path.join(GPATH,'dyskt.log.conf')
logging.config.fileConfig(logpath)

#### OUR EXCEPTIONS
class DySKTException(Exception): pass
class DySKTConfException(DySKTException): pass
class DySKTParamException(DySKTException): pass
class DySKTRuntimeException(DySKTException): pass

def parsechlist(pattern,ptype):
    """
      parse channel list pattern of type ptype = oneof {'scan','pass'} and return
      a list of tuples (ch,chwidth)
    """
    if not pattern: chs,ws = [],[]
    else:
        # split the pattern by ch,width separator
        chs,ws = pattern.split(':')

        # parse channel portion
        if not chs: chs = []
        else:
            if chs.lower().startswith('b'): # band specification
                band = chs[1:]
                if band == '2.4':
                    chs = sorted(channels.ISM_24_C2F.keys())
                elif band == '5':
                    chs = sorted(channels.UNII_5_C2F.keys())
                else:
                    raise ValueError("Band specification %s for %s not supported" % (chs,ptype))
            elif '-' in chs: # range specification
                [l,u] = chs.split('-')
                chs = [c for c in xrange(int(l),int(u)+1) if c in channels.channels()]
            else: # list or single specification
                try:
                    chs = [int(c) for c in chs.split(',')]
                except ValueError:
                    raise ValueError("Invalid channel list specification %s for %s" % (chs,ptype))

            # parse width portion
            if not ws or ws.lower() == 'all': ws = []
            else:
                if ws.lower() == "noht": ws = [None,'HT20']
                elif ws.lower() == "ht": ws = ['HT40+','HT40-']
                else: raise ValueError("Invalid specification for width %s for %s" % (ws,ptype))

    # compile all possible combinations
    if (chs,ws) == ([],[]):
        if ptype == 'scan': return [(ch,chw) for chw in iw.IW_CHWS for ch in channels.channels()]
    elif not chs: return [(ch,chw) for chw in ws for ch in channels.channels()]
    elif not ws: return [(ch,chw) for chw in iw.IW_CHWS for ch in chs]
    else:
        return [(ch,chw) for chw in ws for ch in chs]

    return [],[]

# WASP STATES
DYSKT_INVALID         = -1 # dyskt is unuseable
DYSKT_CREATED         =  0 # dyskt is created but not yet started
DYSKT_RUNNING         =  1 # dyskt is currently executing
DYSKT_PAUSED_RECON    =  2 # dyskt recon radio is paused
DYSKT_PAUSED_COLL     =  3 # dyskt collection radio is paused
DYSKT_PAUSED_BOTH     =  4 # both radios are paused
DYSKT_EXITING         =  5 # dyskt has finished execution loop
DYSKT_DESTROYED       =  6 # dyskt is destroyed

class DySKT(object):
    """ DySKT - primary process of the Wraith sensor """
    def __init__(self,conf=None):
        """ initialize variables """
        # get parameters
        self._cpath = conf if conf else os.path.join(GPATH,'dyskt.conf')
        
        # internal variables
        self._state = DYSKT_INVALID # current state
        self._conf = {}             # dyskt configuration dict
        self._halt = None           # the stop event
        self._pConns = None         # token pipes for children
        self._ic = None             # internal comms queue
        self._rto = None            # data collation/forwarding
        self._rr = None             # recon radio
        self._cr = None             # collection radio
        self._rd = None             # regulatory domain
    
    def _create(self):
        """ create DySKT and member processes """
        # read in and validate the conf file 
        self._readconf()

        # intialize shared objects
        self._halt = mp.Event() # our stop event
        self._ic = mp.Queue()   # comms for children
        self._pConns = {}       # dict of connections to children

        # initialize children
        # Each child is expected to initialize in the _init_ function and throw
        # a RuntimeError failure
        logging.info("Initializing subprocess...")
        try:
            # start RTO first
            logging.info("Starting RTO")
            (conn1,conn2) = mp.Pipe()
            self._pConns['rto'] = conn1
            self._rto = RTO(self._ic,conn2,self._conf)

            # set the region? if so, do it prior to starting the RadioController
            rd = self._conf['local']['region']
            if rd:
                logging.info("Setting regulatory domain to %s",rd)
                self._rd = iw.regget()
                iw.regset(rd)
                if iw.regget() != rd:
                    logging.warn("Regulatory domain %s may not have been set",rd)
                else:
                    logging.info("Regulatory domain set to %s",rd)

            # recon radio is mandatory
            logging.info("Starting Reconnaissance Radio")
            (conn1,conn2) = mp.Pipe()
            self._pConns['recon'] = conn1
            self._rr = RadioController(self._ic,conn2,self._conf['recon'])

            # collection if present
            if self._conf['collection']:
                try:
                    logging.info("Starting Collection Radio")
                    (conn1,conn2) = mp.Pipe()
                    self._pConns['collection'] = conn1
                    self._cr = RadioController(self._ic,conn2,self._conf['collection'])
                except RuntimeError as e:
                    # continue without collector, but log it
                    logging.warning("Collection Radio (%s), continuing without",e)
        except RuntimeError as e:
            # e should have the form "Major:Minor:Description"
            ms = e.message.split(':')
            logging.error("%s (%s) %s",ms[0],ms[1],ms[2])
            self._state = DYSKT_INVALID
        except Exception as e:
            # catchall
            logging.error(e)
            self._state = DYSKT_INVALID
        else:
            # start children execution
            self._state = DYSKT_CREATED
            self._rr.start()
            if self._cr: self._cr.start()
            self._rto.start()

    def _destroy(self):
        """ destroy DySKT cleanly """
        # change our state
        self._state = DYSKT_EXITING

        # reset regulatory domain if necessary
        if self._rd:
            try:
                logging.info("Resetting regulatory domain")
                iw.regset(self._rd)
                if iw.regget() != self._rd: raise RuntimeError
            except:
                logging.warn("Failed to reset regulatory domain")

        # halt main execution loop & send out poison pills
        # put a token on the internal comms from us to break the RTO out of
        # any holding for data block
        logging.info("Stopping Sub-processes")
        self._halt.set()
        self._ic.put(('dyskt',time.time(),'!CHECK!',[]))
        for key in self._pConns:
            try:
                self._pConns[key].send('!STOP!')
            except IOError:
                # ignore any broken pipe errors
                pass
            self._pConns[key].close()
        while mp.active_children(): time.sleep(0.5)

        # change our state
        self._state = DYSKT_DESTROYED

    @property
    def state(self): return self._state

    def start(self):
        """ start execution """
        # setup signal handlers for pause(s),resume(s),stop
        signal.signal(signal.SIGINT,self.stop)   # CTRL-C and kill -INT stop
        signal.signal(signal.SIGTERM,self.stop)  # kill -TERM stop

        # initialize, quit on failure
        logging.info("**** Starting DySKT %s ****" % dyskt.__version__)
        self._create()
        if self.state == DYSKT_INVALID:
            # make sure we do not leave system in corrupt state (i.e. no wireless nics)
            self._destroy()
            raise DySKTRuntimeException("DySKT failed to initialize, shutting down")

        # set state to running
        self._state = DYSKT_RUNNING

        # execution loop
        while not self._halt.is_set():
            # get message a tuple: (level,originator,type,message)
            for key in self._pConns:
                try:
                    if self._pConns[key].poll():
                        (l,o,t,m) = self._pConns[key].recv()
                        if l == "err":
                            # only process errors involved during execution
                            if DYSKT_CREATED < self.state < DYSKT_EXITING:
                                if o == 'collection':
                                    # allow collection radio to fail and still continue
                                    logging.warning("Collection radio dropped. Continuing...")
                                    self._pConns['collection'].send('!STOP!')
                                    self._pConns['collection'].close()
                                    del self._pConns['collection']
                                    mp.active_children()
                                else:
                                    logging.error("%s failed. (%s) %s",o,t,m)
                                    self.stop()
                        elif l == "warn": logging.warning("%s: (%s) %s",o,t,m)
                        elif l == "info": logging.info("%s: (%s) %s",o,t,m)
                except Exception as e:
                    # blanke exception
                    logging.error("DySKT failed. (Unknown) %s",e)
            time.sleep(1)

    # noinspection PyUnusedLocal
    def stop(self,signum=None,stack=None):
        """ stop execution """
        if DYSKT_RUNNING <= self.state < DYSKT_EXITING:
            logging.info("**** Stopping DySKT ****")
            self._destroy()

    def _readconf(self):
        """ read in config file at cpath """
        logging.info("Reading configuration file...")
        conf = ConfigParser.RawConfigParser()
        if not conf.read(self._cpath):
            raise DySKTConfException('%s is invalid' % self._cpath)

        # intialize conf to empty dict
        self._conf = {}

        try:
            # read in the recon radio configuration
            self._conf['recon'] = self._readradio(conf,'Recon')
            try:
                # catch any collection exceptions and log a warning
                if conf.has_section('Collection'):
                    self._conf['collection'] = self._readradio(conf,'Collection')
                else:
                    self._conf['collection'] = None
                    logging.info("No collection radio specified")
            except (ConfigParser.NoSectionError,ConfigParser.NoOptionError,
                    RuntimeError,ValueError):
                logging.warning("Invalid collection specification. Continuing without...")

            # GPS section
            self._conf['gps'] = {}
            self._conf['gps']['fixed'] = conf.getboolean('GPS','fixed')
            if self._conf['gps']['fixed']:
                self._conf['gps']['lat'] = conf.getfloat('GPS','lat')
                self._conf['gps']['lon'] = conf.getfloat('GPS','lon')
                self._conf['gps']['alt'] = conf.getfloat('GPS','alt')
                self._conf['gps']['dir'] = conf.getfloat('GPS','heading')
            else:
                self._conf['gps']['port'] = conf.getint('GPS','port')
                self._conf['gps']['id'] = conf.get('GPS','devid')
                self._conf['gps']['poll'] = conf.getfloat('GPS','poll')
                self._conf['gps']['epx'] = conf.getfloat('GPS','epx')
                self._conf['gps']['epy'] = conf.getfloat('GPS','epy')

            # Storage section
            self._conf['store'] = {'host':conf.get('Storage','host'),
                                   'port':conf.getint('Storage','port')}

            # Local section
            self._conf['local'] = {'region':None,'c2c':None}
            if conf.has_option('Lcoal','C2C'):
                self._conf['local']['c2c'] = conf.getint('Local','C2C')
            if conf.has_option('Local','region'):
                reg = conf.get('Local','region')
                if len(reg) != 2:
                    logging.warn("Regulatory domain %s is invalid" % reg)
                else:
                    self._conf['local']['region'] = conf.get('Local','region')
        except (ConfigParser.NoSectionError,ConfigParser.NoOptionError) as e:
            raise DySKTConfException("%s" % e)
        except (RuntimeError,ValueError) as e:
            raise DySKTConfException("%s" % e)

    def _readradio(self,conf,rtype='Recon'):
        """ read in the rtype radio configuration from conf and return parsed dict """
        # don't bother if specified radio is not present
        if not conf.get(rtype,'nic') in wifaces():
            raise RuntimeError("Radio %s not present/not wireless" % conf.get(rtype,'nic'))

        # get nic and set role setting default antenna config
        r = {'nic':conf.get(rtype,'nic'),
             'spoofed':None,
             'ant_gain':0.0,
             'ant_loss':0.0,
             'ant_offset':0.0,
             'ant_type':0.0,
             'desc':"unknown",
             'scan_start':None,
             'role':rtype.lower(),
             'antennas':{}}

        # get optional properties
        if conf.has_option(rtype,'spoof'): r['spoofed'] = conf.get(rtype,'spoof')
        if conf.has_option(rtype,'desc'):  r['desc'] = conf.get(rtype,'desc')

        # process antennas - get the number first
        try:
            nA = conf.getint(rtype,'antennas') if conf.has_option(rtype,'antennas') else 0
        except ValueError:
            nA = 0

        if nA:
            # antennas has been specified, force correct/valid specifications
            try:
                gain = map(float,conf.get(rtype,'antenna_gain').split(','))
                if len(gain) != nA: raise RuntimeError('gain')
                atype = conf.get(rtype,'antenna_type').split(',')
                if len(atype) != nA: raise RuntimeError('type')
                loss = map(float,conf.get(rtype,'antenna_loss').split(','))
                if len(loss) != nA: raise RuntimeError('loss')
                rs = conf.get(rtype,'antenna_xyz').split(',')
                xyz = []
                for t in rs: xyz.append(tuple(map(int,t.split(':'))))
                if len(xyz) != nA: raise RuntimeError('xyz')
            except ConfigParser.NoOptionError as e:
                logging.warn("Antenna %s not specified" % e)
                #raise DySKTConfException("%s" % e)
            except ValueError as e:
                logging.warn("Invalid type for %s antenna configuration - %s")
            except RuntimeError as e:
                logging.warn("Antenna %s has invalid number of specifications" % e)
            else:
                r['antennas']['num'] = nA
                r['antennas']['gain'] = gain
                r['antennas']['type'] = atype
                r['antennas']['loss'] = loss
                r['antennas']['xyz'] = xyz
        else:
            # none, set all empty
            r['antennas']['num'] = 0
            r['antennas']['gain'] = []
            r['antennas']['type'] = []
            r['antennas']['loss'] = []
            r['antennas']['xyz'] = []

        # get scan pattern
        r['dwell'] = conf.getfloat(rtype,'dwell')
        if r['dwell'] <= 0: raise ValueError("dwell must be > 0")
        r['scan'] = parsechlist(conf.get(rtype,'scan'),'scan')
        r['pass'] = parsechlist(conf.get(rtype,'pass'),'pass')
        if conf.has_option(rtype,'scan_start'):
            try:
                scanspec = conf.get(rtype,'scan_start')
                if ':' in scanspec:
                    (ch,chw) = scanspec.split(':')
                else:
                    ch = scanspec
                    chw = None
                ch = int(ch) if ch else r['scan'][0][0]
                if not chw in iw.IW_CHWS: chw = r['scan'][0][1]
                r['scan_start'] = (ch,chw) if (ch,chw) in r['scan'] else r['scan'][0]
            except ValueError:
                # use default
                r['scan_start'] = r['scan'][0]
        else:
            r['scan_start'] = r['scan'][0]

        return r

if __name__ == 'dyskt':
    try:
        # setup the argument parser
        desc = "DySKT %s - (C) %s %s" % (dyskt.__version__,
                                         dyskt.__date__.split(" ")[1],
                                         dyskt.__author__)
        opts = ap.ArgumentParser(description=desc)
        opts.add_argument("--config",help="load specified configuration file")
        args = opts.parse_args()
        
        # set optional values
        cpath = args.config if args.config else None
        
        # verify validity
        if cpath:
            if not os.path.exists(cpath):
                logging.error("Config file %s does not exits" % cpath)
                raise DySKTConfException("Config file %s does not exist" % cpath)
        
        # create DySKT and start execution
        logging.info("DySKT %s",dyskt.__version__)
        skt = DySKT(cpath)
        skt.start()
    except DySKTConfException as err:
        logging.error("Configuration Error: %s",err)
    except DySKTParamException as err:
        logging.error("Parameter Error: %s",err)
    except DySKTRuntimeException as err:
        logging.error("Runtime Error: %s",err)
    except DySKTException as err:
        logging.error("General Error: %s",err)
    except Exception as err:
        logging.exception("Unknown Error: %s",err)