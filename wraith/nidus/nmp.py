#!/usr/bin/env python

""" nmp.py: Nidus message protocol definition 

Defines the nidus message protocol. A simple definition of the nidus message protocol: 

Nidus expects six major message types Radio, GPSD, Frame, GPS, Status and Sensor
 DEVICE: state of given device has changed 
 RADIO: details about an wireless network interface card
 ANTENNA: antenna details
 RADIO_EVENT: details of radio changing 'state'
 GPSD: details about a gps device
 FRAME: a raw 802.11 frame
 GPS: gps location data

Briefly, each message will follow (NOTE: There cannot be a space betw/ the 
colons and the following data, control character) the below format:
 
 <SOH>*TYPE:<STX>FIELDS<ETX><LF><CR><EOT>
or
 \x01*TYPE:\x02FIELDS\x03\x12\x15\x04 

where TYPE is one {STATUS,SENSOR,RADIO,GPDS,FRAME,GPS} and FIELDS is a space 
delimited string as defined (for TYPE) below. Fields are defined in three 
variables:
 TYPE_FIELDS - list of each expected field name at expected index
 TYPE_WFIELDS - list of tuples (field name, field type)
 TYPE_FIELDNAME1 - index of field name 1 into TYPE_FIELDS, TYPE_WFIELDS
 ...
 TYPE_FIELDNAMEn - index of field name n into TYPE_FIELDS, TYPE_WFIELDS
NOTE:
 o Any field that might possibly contain spaces or control characters must be 
   delimited by \x1EFB\x1F \x1FFE\x1E
 o Fields that are lists are formatted as strings of comma separated values

"""
__name__ = 'nmp'
__license__ = 'GPL v3.0'
__version__ = '0.0.3'
__date__ = 'March 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

#import datetime as dt

class NMPException(Exception): pass

# nidus message protocol header pattern
NMP = r'\x01\*(\w*)\:\x02(.*)'

# conversions
def str2bool(s): return bool(int(s))
def str2ints(s): return [int(x) for x in s.split(',')]
def str2float(s): return None if s == 'nan' else float(s)

def tokenize(f):
        """ parses string f into list of tokens """
        token=''
        tokens=[]
        buff=False
        j = 0
        while j != len(f):
            # if char is part of a buffer, flip buff value
            # if char is a space and buffer is set keep it
            # if char is a space and buffer isnt set, append the token & make new
            # otherwise append the char to current token
            if f[j] == '\x1E' and f[j:j+4] == '\x1EFB\x1F' and not buff:
                j += 3
                buff = True
            elif f[j] == '\x1F' and f[j:j+4] == '\x1FFE\x1E' and buff:
                j += 3
                buff = False
            elif f[j] == ' ':
                if buff: token += f[j]
                else:
                    tokens.append(token)
                    token = ''
            else:
                token += f[j]
            j += 1

        # append the hanging token and return the list
        if token: tokens.append(token)
        return tokens

def data2dict(data,msg):
    """
     converts data, list of incoming records to a dict d such that for each 
     i in data, d[name<i>] = type<i>(data<i>) where name and type are defined 
     as tuples in the <msg>_WFIELDS 
    """
    ds = iter(data)
    try:
        return {n: f(next(ds)) for n,f in eval(msg+'_WFIELDS')}
    except Exception as e:
        raise NMPException, "Convert %s failed: %s" % (msg,e)

#### DEVICE ####
# message signifying a start or stop of a device
DEVICE_FIELDS = ['ts','type','id','state']
DEVICE_WFIELDS = [('ts',str),('type',str),('id',str),('state',str2bool)]
DEVICE_TIMESTAMP = 0 # timestamp
DEVICE_TYPE      = 1 # type of device one of {'sensor','radio','gpsd'}
DEVICE_ID        = 2 # id of the device (hostname, mac or device id)
DEVICE_STATE     = 3 # true = up, false = down

#### PLATFORM ####
PLATFORM_FIELDS = ['os','dist','osv','name','kernel','machine','pyv','bits','link',
                   'compiler','libcv','regdom']
PLATFORM_WFIELDS = [('os',str),('dist',str),('osv',str),('name',str),('kernel',str),
                    ('machine',str),('pyv',str),('bits',str),('link',str),
                    ('compiler',str),('libcv',str),('regdom',str)]
PLATFORM_OS        =  0 # os name
PLATFORM_OS_DIST   =  1 # os distribution
PLATFORM_OS_VERS   =  2 # os version
PLATFORM_OS_NAME   =  3 # os name i.e. Narwhal
PLATFORM_KERNEL    =  4 # os kernel version
PLATFORM_MACHINE   =  5 # os architecture i.e. i386
PLATFORM_PY_VERS   =  6 # python version
PLATFORM_PY_BITS   =  7 # python interpreter bit architecture
PLATFORM_PY_LINK   =  8 # python interpreter linkage
PLATFORM_COMPILER  =  9 # python compiler/version
PLATFORM_LIBC_VERS = 10 # libc version
PLATFORM_REG_DOM   = 11 # current regulatory domain

#### RADIO ####
RADIO_FIELDS = ['ts','mac','role','spoofed','phy','nic','vnic','driver','chipset',
                'standards','channels','txpwr','desc','ant_type','ant_gain',
                'ant_loss','ant_offset']
RADIO_WFIELDS = [('ts',str),('mac',str),('role',str),('spoofed',str),('phy',str),
                 ('nic',str),('vnic',str),('driver',str),('chipset',str),('standards',str),
                 ('channels',str2ints),('txpwr',int),('desc',str)]
RADIO_TIMESTAMP  =  0 # ts of message
RADIO_MAC        =  1 # physical mac address of radio
RADIO_ROLE       =  2 # the role i.e. assault, recon
RADIO_SPOOFED    =  3 # virtual mac address (if any) of radio
RADIO_PHY        =  4 # the phy of the radio
RADIO_NIC        =  5 # the nic of the radio
RADIO_VNIC       =  6 # the virtual nic of the radio
RADIO_DRIVER     =  7 # the radio driver
RADIO_CHIPSET    =  8 # and chipset
RADIO_STANDARDS  =  9 # 802.11 standards radio implements
RADIO_CHANNELS   = 10 # channels supported
RADIO_TXPWR      = 11 # transmit power in dB
RADIO_DESC       = 12 # a short desc

RADIO_EVENT_FIELDS = ['ts','mac','event','params']
RADIO_EVENT_WFIELDS = [('ts',str),('mac',str),('event',str),('params',str)]
RADIO_EVENT_TIMESTAMP = 0 # timestamp of event
RADIO_EVENT_MAC       = 1 # mac address of radio
RADIO_EVENT_EVENT     = 2 # the event one of {'scan','hold','listen','fail'}
RADIO_EVENT_PARAMS    = 3 # free-form parameters of event

#### ANTENNA ####
ANTENNA_FIELDS = ['ts','mac','index','type','gain','loss','x','y','z']
ANTENNA_WFIELDS = [('ts',str),('mac',str),('index',int),('type',str),('gain',float),
                   ('loss',float),('x',int),('y',int),('z',int)]
ANTENNA_TIMESTAMP = 0
ANTENNA_MAC   = 1
ANTENNA_INDEX = 2
ANTENNA_TYPE  = 3
ANTENNA_GAIN  = 4
ANTENNA_LOSS  = 5
ANTENNA_X     = 6
ANTENNA_Y     = 7
ANTENNA_Z     = 8

#### GPSD ####
GPSD_FIELDS = ['ts','id','vers','flags','driver','bps','path']
GPSD_WFIELDS = [('ts',str),('id',str),('vers',str),('flags',int),('driver',str),
                ('bps',int),('path',str)]
GPSD_TIMESTAMP = 0
GPSD_ID        = 1
GPSD_VERSION   = 2
GPSD_FLAGS     = 3
GPSD_DRIVER    = 4
GPSD_BPS       = 5
GPSD_PATH      = 6

#### DATA ####

#### FRAME ####
FRAME_FIELDS = ['ts','mac','frame']
FRAME_WFIELDS = [('ts',str),('mac',str),('frame',str)]
FRAME_TIMESTAMP = 0 # timestamp of frame
FRAME_RID       = 1 # mac address of collecting radio
FRAME_FRAME     = 2 # the frame

#### GPS ####
GPS_FIELDS = ['ts','id','fix','coord','alt','dir',
              'spd','exp','epy','xdop','ydop','pdop']
GPS_WFIELDS = [('ts',str),('id',str),('fix',int),('coord',str),('alt',str2float),
               ('dir',str2float),('spd',str2float),('epx',float),('epy',float),
               ('xdop',float),('ydop',float),('pdop',float)]
GPS_TIMESTAMP =  0 # timestamp of geolocation
GPS_ID        =  1 # id of device collecting this
GPS_FIX       =  2 # 'quality' of the fix, -1 = fixed
GPS_COORD     =  3 # MGRS grid coordinate
GPS_ALT       =  4 # altitude
GPS_DIR       =  5 # heading/direction
GPS_SPD       =  6 # speed
GPS_EPX       =  7 # error in latitude
GPS_EPY       =  8 # error in longitude
GPS_XDOP      =  9 # cross-track dilution of precision
GPS_YDOP      = 10 # cross-track dilution of precision
GPS_PDOP      = 11 # positon dilution of precision
