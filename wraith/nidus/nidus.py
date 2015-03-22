#!/usr/bin/env python

""" nidus.py: SocketServer collecting data from Wasp sensors 

Server frontend to store collected information to database
"""
__name__ = 'nidus'
__license__ = 'GPL v3.0'
__version__ = '0.0.3'
__date__ = 'September 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import os                  # for path validations
import re                  # pattern matching for parsing
import signal              # signal processing
import select              # select function
import socket              # socket functions
import logging             # log
import logging.config      # log configuration
import logging.handlers    # handlers for log
import argparse as ap      # cmd line argument parsing
import SocketServer as ss  # socket server
import nidusdb  # nidus datastorage interface
from wraith import nidus   # top level package
from nmp import NMP        # nidus message protocol regular expression

#### set up log
# have to configure absolute path
GPATH = os.path.dirname(os.path.abspath(__file__))
logpath = os.path.join(GPATH,'nidus.log.conf')
logging.config.fileConfig(logpath)

# CONF FILE path
global CONFPATH

#### OUR EXCEPTIONS
class NidusException(Exception): pass
class NidusConfException(NidusException): pass
class NidusParamException(NidusException): pass
class NidusRuntimeException(NidusException): pass

class NidusRequestHandler(ss.BaseRequestHandler): 
    """ define request handler """
    
    def handle(self):
        """ process client communications """
        caddr = self.client_address[0]
        cport = self.client_address[1]
        logging.info("Sensor %s:%d connected...",caddr,cport)
        
        # get interface to databse
        connected = True
        try:
            # interface to db
            db = nidusdb.NidusDB(CONFPATH)
            db.connect() 
        except nidusdb.NidusDBException as e:
            logging.error("DB Interface failed: %s",e)
            return
            
        # serving loop
        while connected:
            try:
                # if server has quit, shut down everything
                if self.server.quit:
                    raise RuntimeError("Nidus Server shut down early")

                # get data and parse
                data = self._recv()
                if data: self._process(data,db)
                else:
                    logging.info("Sensor %s:%d exited...",caddr,cport)
                    connected = False
            except RuntimeError:
                # nidus server shutdown, close out the db
                db.submitdropped()
                connected = False
            except Exception as e:
                # lost connection with sensor, minimize errors to database
                db.submitdropped()
                logging.error("Sensor %s:%d dropped - %s",caddr,cport,e)
                connected = False
        
        # clean up
        db.disconnect()
        self.request.close()

    def _recv(self):
        """ recv - read 1024 byte chunks from sensor until EOT """
        msg = ''
        while len(msg) == 0 or msg[-4:] != "\x03\x12\x15\x04":
            try:
                data = self.request.recv(1024)
                if data == '': return None
                msg += data
            except socket.error as e:
                raise RuntimeError(e)
        return msg

    def _process(self,data,db):
        """ process - parses received data and passes to storage server db """
        rs = data.split("\x03\x12\x15\x04") # split into independent messags
        for r in rs[:-1]:
            # for each message
            try:
                # parse out TYPE and FIELDS - leave fields as string to minimize 
                # memory requirements of a list of tokens
                (t,f) = re.match(NMP,r,re.S).groups()

                # send message to storage db
                if t == 'DEVICE': db.submitdevice(f,self.client_address[0])
                elif t == 'PLATFORM': db.submitplatform(f)
                elif t == 'RADIO': db.submitradio(f)
                elif t == 'ANTENNA': db.submitantenna(f)
                elif t == 'RADIO_EVENT': db.submitradioevent(f)
                elif t == 'GPSD': db.submitgpsd(f)
                elif t == 'FRAME': db.submitframe(f)
                elif t == 'GPS': db.submitgeo(f)
                else:
                    logging.warning("Sensor %s:%d sent data with invalid header %s",
                                    self.client_address[0],
                                    self.client_address[1],
                                    t)
            except AttributeError as e:
                # this is caused by the reg exp
                logging.warning("Sensor %s:%d sent invalid data: \n%s\n%s",
                                self.client_address[0],
                                self.client_address[1],
                                f.__repr__(),e)
            except nidusdb.NidusDBSubmitParseException as e:
                # failure in parsing nidus message protocol
                logging.warning("Sensor %s:%d. Message\n%s\nfailed to parse: %s",
                                self.client_address[0],
                                self.client_address[1],
                                f.__repr__(),e)
            except nidusdb.NidusDBSubmitException as e:
                # failure during datastore submission
                logging.warning("Sensor %s:%d submit: %s",
                                self.client_address[0],
                                self.client_address[1],
                                e)

class NidusServer(ss.ThreadingMixIn, ss.TCPServer):
    daemon_threads = False
    allow_reuse_address = True
    def __init__(self,addr,rh):
        ss.TCPServer.__init__(self,addr,rh)
        self.quit = False
    def stop(self):
        logging.info("NidusServer stopping...")
        self.quit = True
    def start(self):
        logging.info("NidusServer waiting...")
        while not self.quit:
            try:
                (rs,ws,es) = select.select([self],[],[],0.5)
                if self in rs: self.handle_request() 
            except select.error as ex:
                if ex[0] == 4:
                    # hide (4, 'Interrupted system call') select errors 
                    pass
                else:
                    logging.warning(ex)   
        logging.info("NidusServer stopped")

class Nidus(object):
    """ NidusServer """
    def __init__(self):
        """ initialize server """
        self.server = None
    
    def start(self): 
        """ start server execution """
        # signal handlers for shutdown, ctrl-C or kill -TERM
        signal.signal(signal.SIGINT,self.stop)    # CTRL-C stop
        signal.signal(signal.SIGTERM,self.stop)   # stop
        
        self.server = NidusServer(('127.0.0.1',2527),NidusRequestHandler)
        self.server.start()

    # noinspection PyUnusedLocal
    def stop(self,signum=None,stack=None):
        """ stop serving """
        logging.info("Nidus shutting down")
        self.server.quit = True

if __name__ == 'nidus':
    try:
        # command line parsing
        opts = ap.ArgumentParser(description="Nidus %s (C) %s %s" % (nidus.__version__,
                                                                     nidus.__date__.split(" ")[1],
                                                                     nidus.__author__))
        opts.add_argument("--config",help="load specified config file")
        args = opts.parse_args()

        cpath = args.config if args.config else None
        if cpath:
            if not os.path.exists(cpath):
                logging.error("Config file %s does not exist" % cpath)
                raise NidusConfException("Config file %s does not exist" % cpath)
            else:
                CONFPATH = cpath
        else:
            CONFPATH = 'nidus.conf'

        # create Wasp and start execution
        logging.info("Nidus %s",nidus.__version__)
        store = Nidus()
        store.start()
    except NidusConfException as e:
        # w failed to start, no need to stop
        logging.error("Configuration Error: %s",e)