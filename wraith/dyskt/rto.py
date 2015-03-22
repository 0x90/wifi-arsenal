#!/usr/bin/env python

""" rto.py: collates and relays wraith sensor data

Processes and forwards 1) frames from the sniffer(s) 2) gps data (if any) collected
by a pf and 3) messages from tuner(s) and sniffer(s0
"""
__name__ = 'rto'
__license__ = 'GPL v3.0'
__version__ = '0.0.11'
__date__ = 'March 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import platform                            # system details
import sys                                 # python intepreter details
import signal                              # signal processing
import time                                # sleep and timestamps
import socket                              # connection to nidus and gps device
import threading                           # threads
import mgrs                                # lat/lon to mgrs conversion
import gps                                 # gps device access
from Queue import Queue, Empty             # thread-safe queue
import multiprocessing as mp               # multiprocessing
from wraith.utils.timestamps import ts2iso # timestamp conversion
from wraith.radio.iw import regget         # regulatory domain

class GPSPoller(threading.Thread):
    """ periodically checks gps for current location """
    def __init__(self,ev,poll,did,epx,epy,host='127.0.0.1',port=2947):
        """
         ev - event queue between rto and this Thread
         tC - DySKT token connnection
         poll - time to poll gps device
         did - device id
         epx - quality control
         epy - quality control
         host - device address
         port - device port
        """
        threading.Thread.__init__(self)
        self._done = threading.Event()
        self._eQ = ev      # event queue from radio controller
        self._poll = poll  # poll time
        self._id = did     # device id
        self._qcx = epx    # longitudal qc
        self._qcy = epy    # latitudal qc
        self._gpsd = None  # gps device connection
        self._setup(host,port)

    def _setup(self,host,port):
        """ attempt to connect to device """
        try:
            self._gpsd = gps.gps(host,port)
            self._gpsd.stream(gps.WATCH_ENABLE)
        except socket.error as e:
            raise RuntimeError(e)

    def shutdown(self): self._done.set()

    def run(self):
        """ query for current location """
        # two execution loops - 1) get device details 2) get location

        # Device Details Loop - get complete details or quit on done
        dd = {'id':self._id,
              'version':None,
              'driver':None,
              'bps':None,
              'path':None,
              'flags':None}
        while not dd['flags']:
            if self._done.is_set(): break
            else:
                # loop while data is on serial (could block)
                while self._gpsd.waiting():
                    dev = self._gpsd.next()
                    try:
                        if dev['class'] == 'VERSION':
                            dd['version'] = dev['release']
                        elif dev['class'] == 'DEVICE':
                            # flags will not be present until gpsd has seen identifiable
                            # packets from the device
                            dd['flags'] = dev['flags']
                            dd['driver'] = dev['driver']
                            dd['bps'] = dev['bps']
                            dd['path'] = dev['path']
                    except KeyError:
                        pass
                    if dd['version'] and dd['flags']:
                        # send device details and break from inner loop
                        self._eQ.put(('!DEV!',time.time(),dd))
                        break
            time.sleep(self._poll)

        # Location
        while not self._done.is_set():
            # while there's data, get it (NOTE: this loop may exit without data)
            while self._gpsd.waiting() and not self._done.is_set():
                rpt = self._gpsd.next()
                if rpt['class'] != 'TPV': continue
                geo = {}
                try:
                    # get all values
                    geo['id'] = self._id
                    geo['fix'] = rpt['mode']
                    geo['lat'] = (rpt['lat'],rpt['epy'])
                    geo['lon'] = (rpt['lon'],rpt['epx'])
                    geo['alt'] = rpt['alt'] if 'alt' in rpt else float("nan")
                    geo['dir'] = rpt['track'] if 'track' in rpt else float("nan")
                    geo['spd'] = rpt['spd'] if 'spd' in rpt else float("nan")
                    geo['dop'] = {'xdop':self._gpsd.xdop,
                                  'ydop':self._gpsd.ydop,
                                  'pdop':self._gpsd.pdop}

                    # no error check quality &
                    if rpt['epy'] <= self._qcy and rpt['epx'] <= self._qcx:
                        self._eQ.put(('!GEO!',time.time(),geo))
                    break
                except KeyError: # not all values present
                    pass
                except AttributeError: # not all dop values present
                    pass
            time.sleep(self._poll)

        # close out connection
        self._gpsd.close()

class RTO(mp.Process):
    """ RTO - handles further processing of raw frames from the sniffer """
    def __init__(self,comms,conn,conf):
        """
         initializes RTO
         comms - internal communication
         conn - connection to/from DySKT
         conf - necessary config details
        """
        mp.Process.__init__(self)
        self._comms = comms                # communications queue
        self._conn = conn                  # message queue to/from DySKT
        self._mgrs = None                  # lat/lon to mgrs conversion
        self._conf = conf['gps']           # configuration for gps/datastore
        self._nidus = None                 # nidus server
        self._flt = None                   # geo thread
        self._q = None                     # our queue to gps poller
        self._setup(conf['store']['host'],conf['store']['port'])

    def _setup(self,host,port):
        """ connect to Nidus for data transfer and pass sensor up event """
        try:
            # get mgrs converter
            self._mgrs = mgrs.MGRS()

            # connect to data store
            self._nidus = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self._nidus.connect((host,port))
        except socket.error as e:
            raise RuntimeError("RTO:Nidus:%s" % e)
        except Exception as e:
            raise RuntimeError("RTO:Unknown:%s" % e)

    def terminate(self): pass
    
    def run(self):
        """ run execution loop """
        # ignore signals being used by main program
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        signal.signal(signal.SIGTERM,signal.SIG_IGN) 

        # radio map: maps callsigns to mac addr
        rmap = {}

        # send sensor up notification, platform details and gpsid
        gpsid = None
        ret = self._send('DEVICE',time.time(),['sensor',socket.gethostname(),1])
        if ret: self._conn.send(('err','RTO','Nidus',ret))
        else:
            ret = self._send('PLATFORM',time.time(),self._pfdetails())
            if ret: self._conn.send(('err','RTO','Nidus',ret))
            else: gpsid = self._setgpsd()

        # execution loop
        tkn = None
        while tkn != '!STOP!':
            # 1. anything from DySKT
            if self._conn.poll():
                tkn = self._conn.recv()
                if tkn != '!STOP!':
                    self._conn.send(('warn','RTO','Token',"unknown %s" % tkn))
                else:
                    continue

            # 2. gps device/frontline trace?
            if self._flt:
                try:
                    (t,ts,msg) = self._q.get_nowait()
                except Empty: # no new messages
                    pass
                else:
                    if t == '!DEV!': # device up message
                        gpsid = msg['id']
                        self._conn.send(('info','RTO','GPSD',"%s initiated" % gpsid))
                        ret = self._send('GPSD',ts,msg)
                        if ret: self._conn.send(('err','RTO','Nidus',ret))
                    elif t == '!GEO!': # frontline trace
                        if not gpsid:
                            self._conn.send(('warn','RTO','GPSD','out of order'))
                        ret = self._send('GPS',ts,msg)
                        if ret: self._conn.send(('err','RTO','Nidus',ret))

            # 3. queued data from radios (possibly DySKT)
            ev = msg = None
            try:
                rpt = self._comms.get() # blocking call
                (cs,ts,ev,msg,_) = rpt.report

                # DySKT pushes a token onto the internal comms allowing us to
                # break the blocking call and check the token
                if cs == 'dyskt': continue
                if ev == '!UP!': # should be the 1st message we get from radio(s)
                    # NOTE: send the radio, nidus will take care of setting the
                    # radio device to up. Send each antenna separately
                    rmap[cs] = msg['mac']
                    self._conn.send(('info','RTO','Radio',"%s initiated" % cs))
                    ret = self._send('RADIO',ts,msg)
                    if ret: self._conn.send(('err','RTO','Nidus',ret))
                    else:
                        # send antennas
                        for i in xrange(msg['nA']):
                            ret = self._send('ANTENNA',ts,{'mac':msg['mac'],
                                                           'index':i,
                                                           'type':msg['type'][i],
                                                           'gain':msg['gain'][i],
                                                           'loss':msg['loss'][i],
                                                           'x':msg['x'][i],
                                                           'y':msg['y'][i],
                                                           'z':msg['z'][i]})
                            if ret:
                                self._conn.send(('err','RTO','Nidus',ret))
                                break
                #elif ev == '!DOWN!':
                #    pass
                elif ev == '!FAIL!':
                    # send fail to nidus, notify DySKT & delete cs from rmap
                    ret = self._send('RADIO_EVENT',ts,[rmap[cs],'fail',msg])
                    if ret: self._conn.send(('err','RTO','Nidus',ret))
                    del rmap[cs]
                elif ev == '!SCAN!':
                    # compile the scan list into a string
                    sl = ",".join(["%d:%s" % (c,w) for (c,w) in msg])
                    ret = self._send('RADIO_EVENT',ts,[rmap[cs],'scan',sl])
                    if ret: self._conn.send(('err','RTO','Nidus',ret))
                #elif ev == '!LISTEN!':
                #    pass
                elif ev == '!HOLD!':
                    ret = self._send('RADIO_EVENT',ts,[rmap[cs],'hold',msg])
                    if ret: self._conn.send(('err','RTO','Nidus',ret))
                #elif ev == '!PAUSE!':
                #    pass
                elif ev == '!FRAME!': # pass the frame on
                    ret = self._send('FRAME',ts,[rmap[cs],msg])
                    if ret: self._conn.send(('err','RTO','Nidus',ret))
                else: # unidentified event type, notify leader
                    self._conn.send(('warn','RTO','Radio',
                                     "unidentified event %s" % ev))
            except IndexError as e: # something wrong with antenna indexing
                self._conn.send(('err','RTO',"Radio","misconfigured antennas"))
            except KeyError as e: # a radio sent a message without initiating
                self._conn.send(('warn','RTO','Radio %s' % e,
                                 "sent data %s of type %s w/o 'initiating'" % (ev,msg)))
            except Exception as e: # handle catchall error
                self._conn.send(('err','RTO','Unknown',e))

        # notify Nidus of closing (radios, sensor,gpsd). hopefully no errors on send
        ts = time.time()
        for cs in rmap: self._send('DEVICE',ts,['radio',rmap[cs],0])
        if gpsid: self._send('DEVICE',ts,['gpsd',gpsid,0])
        self._send('DEVICE',ts,['sensor',socket.gethostname(),0])

        # shut down
        if not self.shutdown():
            try:
                self._conn.send(('warn','RTO','Shutdown',"Incomplete shutdown"))
            except IOError:
                # most likely DySKT(.py) closed their side of the pipe
                pass

    def shutdown(self):
        """ clean up. returns whether a full reset or not occurred """
        # try shutting down & resetting radio (if it failed we may not be able to)
        clean = True
        try:
            # stop GPSPoller
            if self._flt: self._flt.stop()

            # close socket and connection
            self._nidus.close()
            self._conn.close()
        except:
            clean = False
        return clean

#### send helper functions

    def _send(self,t,ts,d):
        """
         send - sends message msg m of type t with timestamp ts to Nidus
          t - message type
          ts - message timestamp
          d - data
         returns None on success otherwise returns reason for failure
        """
        # convert the timestamp to utc isoformat before crafting
        ts = ts2iso(ts)
        
        # craft the message
        try:
            send = "\x01*%s:\x02" % t
            if t == 'DEVICE': send += self._craftdevice(ts,d)
            elif t == 'PLATFORM': send += self._craftplatform(d)
            elif t == 'RADIO': send += self._craftradio(ts,d)
            elif t == 'ANTENNA': send += self._craftantenna(ts,d)
            elif t == 'GPSD': send += self._craftgpsd(ts,d)
            elif t == 'FRAME': send += self._craftframe(ts,d)
            elif t == 'GPS': send += self._craftflt(ts,d,self._mgrs)
            elif t == 'RADIO_EVENT': send += self._craftradioevent(ts,d)
            send += "\x03\x12\x15\04"
            if not self._nidus.send(send): return "Nidus socket closed unexpectantly"
            return None
        except socket.error, ret:
            return ret
        except Exception, ret:
            return ret

    def _setgpsd(self):
        """ determines whether to use no gps, fixed gps or gps device """
        gpsid = None
        if self._conf:
            if self._conf['fixed']:
                # send a 'fake' gps device and the fixed location
                gpsid = 'xxxx:xxxx'
                ts = time.time()
                ret = self._send('GPSD',ts,{'id':gpsid,
                                            'version':'0.0',
                                            'flags':0,
                                            'driver':'static',
                                            'bps':0,
                                            'path':'None'})
                if ret: self._conn.send(('err','RTO','Nidus',ret))
                ret = self._send('GPS',time.time(),{'fix':-1,
                                                    'id':gpsid,
                                                    'lat':(self._conf['lat'],0.0),
                                                    'lon':(self._conf['lon'],0.0),
                                                    'alt':self._conf['alt'],
                                                    'dir':self._conf['dir'],
                                                    'spd':0.0,
                                                    'dop':{'xdop':1,
                                                           'ydop':1,
                                                           'pdop':1}})
                if ret: self._conn.send(('err','RTO','Nidus',ret))
            else:
                # start the GPSPoller thread
                self._q = Queue()
                try:
                    self._flt = GPSPoller(self._q,self._conf['poll'],self._conf['id'],
                                          self._conf['epx'],self._conf['epy'],
                                          self._conf['host'],self._conf['port'])
                except RuntimeError as e:
                    self._conn.send(('warn','RTO','GPS',"Failed to connnect %s" %e))
                else:
                    self._flt.start()
                    self._conn.send(('info','RTO','GPS',"Started GPS Polling"))
        return gpsid

    @staticmethod
    def _pfdetails():
        """ get platform details as dict and return """
        d = {'rd':None,'dist':None,'osvers':None,'name':None}
        d['os'] = platform.system().capitalize()
        try:
            d['dist'],d['osvers'],d['name'] = platform.linux_distribution()
        except:
            pass
        try:
            d['rd'] = regget()
        except:
            pass
        d['kernel'] = platform.release()
        d['arch'] = platform.machine()
        d['pyvers'] = "%d.%d.%d" % (sys.version_info.major,
                                    sys.version_info.minor,
                                    sys.version_info.micro)
        d['bits'],d['link'] = platform.architecture()
        d['compiler'] = platform.python_compiler()
        d['libcvers'] = " ".join(platform.libc_ver())
        return d

    @staticmethod
    def _craftdevice(ts,d):
        """ create body of device message """
        return "%s %s \x1EFB\x1F%s\x1FFE\x1E %d" % (ts,d[0],d[1],d[2])

    @staticmethod
    def _craftplatform(d):
        """ create body of platform message """
        return "%s \x1EFB\x1F%s\x1FFE\x1E %s \x1EFB\x1F%s\x1FFE\x1E %s %s %s %s %s \x1EFB\x1F%s\x1FFE\x1E \x1EFB\x1F%s\x1FFE\x1E \x1EFB\x1F%s\x1FFE\x1E" % \
                (d['os'],d['dist'],d['osvers'],d['name'],d['kernel'],d['arch'],
                 d['pyvers'],d['bits'],d['link'],d['compiler'],d['libcvers'],d['rd'])

    @staticmethod
    def _craftradio(ts,d):
        """ creates radio message body (d[0] is the radio and r its role """
        return "%s %s %s %s %s %s %s \x1EFB\x1F%s\x1FFE\x1E \x1EFB\x1F%s\x1FFE\x1E %s %s %s \x1EFB\x1F%s\x1FFE\x1E"  % \
               (ts,d['mac'],d['role'],d['spoofed'],d['phy'],d['nic'],d['vnic'],
                d['driver'],d['chipset'],d['standards'],','.join(d['channels']),
                d['txpwr'],d['desc'])

    @staticmethod
    def _craftradioevent(ts,d):
        """ create body of radio event message """
        return "%s %s %s \x1EFB\x1F%s\x1FFE\x1E" % (ts,d[0],d[1],d[2])

    @staticmethod
    def _craftantenna(ts,d):
        """ create body of antenna message """
        return "%s %s %d \x1EFB\x1F%s\x1FFE\x1E %.2f %.2f %d %d %d" %\
               (ts,d['mac'],d['index'],d['type'],d['gain'],d['loss'],d['x'],
                d['y'],d['z'])

    @staticmethod
    def _craftframe(ts,d):
        """ creates body of the frame message """
        return "%s \x1EFB\x1F%s\x1FFE\x1E \x1EFB\x1F%s\x1FFE\x1E" % (ts,d[0],d[1])

    @staticmethod
    def _craftgpsd(ts,d):
        """ create body of gps device message """
        return "%s %s %s %d \x1EFB\x1F%s\x1FFE\x1E %d \x1EFB\x1F%s\x1FFE\x1E" %\
               (ts,d['id'],d['version'],d['flags'],d['driver'],d['bps'],d['path'])

    @staticmethod
    def _craftflt(ts,d,m):
        """ create body of the gps location message """
        return "%s %s %d %s %.2f %.2f %.2f %.3f %.3f %.3f %.3f %.3f" %\
               (ts,d['id'],d['fix'],m.toMGRS(d['lat'][0],d['lon'][0]),d['alt'],
                d['dir'],d['spd'],d['lat'][1],d['lon'][1],d['dop']['xdop'],
                d['dop']['ydop'],d['dop']['pdop'])