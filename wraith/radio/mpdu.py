#!/usr/bin/env python

""" mpdu.py: Mac Protocol Data Unit (MPDU) parsing.

Parses the 802.11 MAC Protocol Data Unit (MPDU) IAW IEED 802.11-2012 we use Std
when referring to IEEE Std 802.11-2012
NOTE:
 It is recommended not to import * as it may cause conflicts with other modules
"""
__name__ = 'mpdu'
__license__ = 'GPL v3.0'
__version__ = '0.1.0'
__date__ = 'January 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import struct
from binascii import hexlify
from wraith.utils.bits import *

class MPDUException(Exception): pass                    # generic mpdu exception
class MPDUUninstantiatedException(MPDUException): pass  # class not instantiated
class MPDUInvalidPropertyException(MPDUException): pass # no such property

# SOME CONSTANTS
BROADCAST = "ff:ff:ff:ff:ff:ff" # broadcast address
MAX_MPDU = 7991                 # maximum mpdu size in bytes
FMT_BO = "="                    # struct format byte order specifier

class MPDU(dict):
    """
     a wrapper class for the underlying mpdu dict
     a MPDU object is a dict with the following mandatory key/value pairs
       - mpdu fields: frames will be FRAMECTRL|DURATION|ADDR1 (and fcs if not
       stripped by the firmware) see Std 8.3.1.3]
      present: an ordered list of mpdu fields
      offset: the number of bytes read from the first byte of frame upto the msdu
       (including any encryption)
      stripped: the number of bytes read from the last byte of the frame upto
       the end of the msdu (including any encryption)
     a MPDU object will also contain key/value pairs for fields present in the
     mpdu as dictated by the structure of the mac header

     the MPDU object will expose 'toplevel' mac layer fields so that users can call
     for example dictMPDU.framectrl rather than dictMPDU['framectrl']. These are
     listed below:
     framectrl, duration, addr1, ..., addr4 (as present), seqctrl, qosctrl
     htc, crypt, fcs

     it will also expose certain sublevel fields:
     vers, type, subtype, flags,

     as well as additional members:
     offset (bytes read from 'front' of frame), stripped (bytes read from 'end' of
     frame), size (total bytes read), present (ordered list of fields present
     in the MPDU)
    """
    def __new__(cls,d=None):
        return super(MPDU,cls).__new__(cls,dict({} if not d else d))

    #### PROPERTIES

    # the following are 'added fields' of an mpdu they will return a default
    # 'empty' value if the mpdu is not instantiated

    @property
    def offset(self):
        # offset is the number of bytes read from byte 0
        try:
            return self['offset']
        except:
            return 0

    @property
    def stripped(self):
        # number of bytes read from the last byte of the frame
        try:
            return self['stripped']
        except:
            return 0

    @property
    def size(self):
        # size is the total number of bytes read (includes fcs and any icv, etc)
        # that are at the end of the frame
        try:
            return self['offset'] + self['stripped']
        except:
            return 0

    @property
    def present(self):
        try:
            return self['present']
        except:
            return []

    # The following are the minimum required fields of a mpdu frame
    # and will raise an unistantiated error if not present

    @property
    def framectrl(self):
        try:
            return self['framectrl']
        except KeyError:
            raise MPDUUninstantiatedException

    @property
    def vers(self):
        try:
            return self['framectrl']['vers']
        except KeyError:
            raise MPDUUninstantiatedException

    @property
    def type(self):
        try:
            return self['framectrl']['type']
        except KeyError:
            raise MPDUUninstantiatedException

    @property
    def subtype(self):
        try:
            return self['framectrl']['subtype']
        except KeyError:
            raise MPDUUninstantiatedException

    @property
    def subtype_desc(self):
        try:
            if self.type == FT_MGMT: return ST_MGMT_TYPES[self.subtype]
            elif self.type == FT_CTRL: return ST_CTRL_TYPES[self.subtype]
            elif self.type == FT_DATA: return ST_DATA_TYPES[self.subtype]
            else: return 'rsrv'
        except KeyError:
            raise MPDUUninstantiatedException

    @property
    def flags(self): # mpdu flags
        try:
            return self['framectrl']['flags']
        except KeyError:
            raise MPDUUninstantiatedException

    @property # mpdu duration
    def duration(self):
        try:
            return self['duration']
        except KeyError:
            raise MPDUUninstantiatedException

    @property # mpdu address 1
    def addr1(self):
        try:
            return self['addr1']
        except KeyError:
            raise MPDUUninstantiatedException

    # the following may or may not be present and will return
    # None if not present

    @property
    def addr2(self): return self['addr2'] if 'addr2' in self else None
    @property
    def addr3(self): return self['addr3'] if 'addr3' in self else None
    @property
    def seqctrl(self): return self['seqctrl'] if 'seqctrl' in self else None
    @property
    def addr4(self): return self['addr4'] if 'addr4' in self else None
    @property
    def qosctrl(self): return self['qos'] if 'qos' in self else None
    @property
    def htc(self): return self['htc'] if 'htc' in self else None
    @property
    def fcs(self): return self['fcs'] if 'fcs' in self else None
    @property
    def crypt(self): return self['l3-crypt'] if 'l3-crypt' in self else None
    @property
    def fixed_params(self): return self['fixed-params'] if 'fixed-params' in self else None
    @property
    def info_els(self): return self['info-elements'] if 'info-elements' in self else None

def parse(frame,hasFCS=False):
    """
     parses the mpdu in frame (where frame is stripped of any layer 1 header)
     and returns a dict d where d will always have key->value pairs for:
      vers: mpdu version (always 0)
      sz: offset of last bytes read from mpdu (not including fcs).
      present: an ordered list of fields present in the frame
      and key->value pairs for each field in present
    """
    # at a minimum, frames will be FRAMECTRL|DURATION|ADDR1 (and fcs if not
    # stripped by the firmware) see Std 8.3.1.3
    try:
        vs,offset = _unpack_from_(_S2F_['framectrl'],frame,0)
        mac = MPDU({'framectrl':{'vers':leastx(2,vs[0]),
                                 'type':midx(2,2,vs[0]),
                                 'subtype':mostx(4,vs[0]),
                                 'flags':_fcflags_(vs[1])},
                    'present':['framectrl'],
                    'offset':offset,
                    'stripped':0})

        # unpack duration, address 1
        vs,mac['offset'] = _unpack_from_(_S2F_['duration'] + _S2F_['addr'],
                                         frame,mac['offset'])
        mac['duration'] = _duration_(vs[0])
        mac['addr1'] = _hwaddr_(vs[1:])
        mac['present'].extend(['duration','addr1'])

        # remove fcs if present (as some functions will eat all remaining bytes
        if hasFCS:
            mac['fcs'],_ = struct.unpack(FMT_BO+'L',frame[-4:])
            frame = frame[:-4]
            mac['stripped'] += 4
    except struct.error as e:
        raise MPDUException("Error unpacking minimum: %s" % e)

    # handle frame types separately
    if mac.type == FT_MGMT: _parsemgmt_(frame,mac)
    elif mac.type == FT_CTRL: _parsectrl_(frame,mac)
    elif mac.type == FT_DATA: _parsedata_(frame,mac)
    else:
        raise MPDUException("unresolved type")

    # process encryption
    if mac.flags['pf']:
        # get the first four bytes of the msdu & run test for encryption type
        bs = struct.unpack_from(FMT_BO+'4B',frame,mac['offset'])
        if bs[3] & 0x20: # 5th (ExtIV) bit is set on the 4th octet, we have WPA/WPA2
            # check the wep seed (2nd byte to determine whether we have WPA/TKIP
            # WEP Seed = (TSC1 | 0x20) & 0x7f
            # see http://www.xirrus.com/cdn/pdf/wifi-demystified/documents_posters_encryption_plotter
            if (bs[0] | 0x20) & 0x7f == bs[1]:
                _tkip_(frame,mac)
            else:
                _ccmp_(frame,mac)
        else: # 5th (ExtIV) bit is not set on the 4th octet we have WEP
            _wep_(frame,mac)

        # add encyrption to present dict
        if 'l3-crypt' in mac: mac['present'].append('l3-crypt')

    # append the fcs to present if necessar
    if hasFCS: mac['present'].append('fcs')

    # return
    return mac

#### FRAME FIELDS Std 8.2.3

# FRAMECTRL|DUR/ID|ADDR1|ADDR2|ADDR3|SEQCTRL|ADDR4|QOS|HTC|BODY|FCS
# BYTES   2      2     6     6     6       2     6   2   4  var   4

# unpack formats
_S2F_ = {'framectrl':'BB',
         'duration':'H',
         'addr':'6B',
         'seqctrl':'H',
         'bactrl':'H',
         'barctrl':'H',
         'qos':"BB",
         'htc':'I',
         'capability':'H',
         'listen-int':'H',
         'status-code':'H',
         'aid':'H',
         'timestamp':'Q',
         'beacon-int':'H',
         'reason-code':'H',
         'algorithm-no':'H',
         'auth-seq':'H',
         'category':'B',
         'action':'B',
         'wep-keyid':'B',
         'fcs':'I'}

#### Frame Control Std 8.2.4.1.1
# Frame Control is 2 bytes and has the following format
#  Protocol Vers 2 bits: always '00'
#  Type 2 bits: '00' Management, '01' Control,'10' Data,'11' Reserved
#  Subtype 4 bits
#  This comes down the wire as:
#       ST|FT|PV|FLAGS
# bits   4| 2| 2|    8
FT_TYPES = ['mgmt','ctrl','data','rsrv']
FT_MGMT              =  0
FT_CTRL              =  1
FT_DATA              =  2
FT_RSRV              =  3
ST_MGMT_TYPES = ['assoc-req','assoc-resp','reassoc-req','reassoc-resp','probe-req',
                 'probe-resp','timing-adv','rsrv','beacon','atim','disassoc','auth',
                 'deauth','action','action_noack','rsrv']
ST_MGMT_ASSOC_REQ    =  0
ST_MGMT_ASSOC_RESP   =  1
ST_MGMT_REASSOC_REQ  =  2
ST_MGMT_REASSOC_RESP =  3
ST_MGMT_PROBE_REQ    =  4
ST_MGMT_PROBE_RESP   =  5
ST_MGMT_TIMING_ADV   =  6 # 802.11p
ST_MGMT_RSRV_7       =  7
ST_MGMT_BEACON       =  8
ST_MGMT_ATIM         =  9
ST_MGMT_DISASSOC     = 10
ST_MGMT_AUTH         = 11
ST_MGMT_DEAUTH       = 12
ST_MGMT_ACTION       = 13
ST_MGMT_ACTION_NOACK = 14
ST_MGMT_RSRV_15      = 15
ST_CTRL_TYPES = ['rsrv','rsrv','rsrv','rsrv','rsrv','rsrv','rsrv','wrapper',
                 'block-ack-req','block-ack','pspoll','rts','cts','ack','cfend',
                 'cfend-cfack']
ST_CTRL_RSRV_0        =  0
ST_CTRL_RSRV_1        =  1
ST_CTRL_RSRV_2        =  2
ST_CTRL_RSRV_3        =  3
ST_CTRL_RSRV_4        =  4
ST_CTRL_RSRV_5        =  5
ST_CTRL_RSRV_6        =  6
ST_CTRL_WRAPPER       =  7
ST_CTRL_BLOCK_ACK_REQ =  8
ST_CTRL_BLOCK_ACK     =  9
ST_CTRL_PSPOLL        = 10
ST_CTRL_RTS           = 11
ST_CTRL_CTS           = 12
ST_CTRL_ACK           = 13
ST_CTRL_CFEND         = 14
ST_CTRL_CFEND_CFACK   = 15
ST_DATA_TYPES = ['data','cfack','cfpoll','cfack_cfpoll','null','null-cfack',
                 'null-cfpoll','null-cfack-cfpoll','qos-data','qos-data-cfack',
                 'qos-data-cfpoll','qos-data-cfack-cfpoll','qos-null','rsrv',
                 'qos-cfpoll','qos-cfack-cfpoll']
ST_DATA_DATA                  =  0
ST_DATA_CFACK                 =  1
ST_DATA_CFPOLL                =  2
ST_DATA_CFACK_CFPOLL          =  3
ST_DATA_NULL                  =  4
ST_DATA_NULL_CFACK            =  5
ST_DATA_NULL_CFPOLL           =  6
ST_DATA_NULL_CFACK_CFPOLL     =  7
ST_DATA_QOS_DATA              =  8
ST_DATA_QOS_DATA_CFACK        =  9
ST_DATA_QOS_DATA_CFPOLL       = 10
ST_DATA_QOS_DATA_CFACK_CFPOLL = 11
ST_DATA_QOS_NULL              = 12
ST_DATA_RSRV_13               = 13
ST_DATA_QOS_CFPOLL            = 14
ST_DATA_QOS_CFACK_CFPOLL      = 15

# Frame Control Flags Std 8.2.4.1.1
# td -> to ds fd -> from ds mf -> more fragments r  -> retry pm -> power mgmt
# md -> more data pf -> protected frame o  -> order
# index of frame types and string titles
_FC_FLAGS_NAME_ = ['td','fd','mf','r','pm','md','pf','o']
_FC_FLAGS_ = {'td':(1 << 0),'fd':(1 << 1),'mf':(1 << 2),'r':(1 << 3),
               'pm':(1 << 4),'md':(1 << 5),'pf':(1 << 6),'o':(1 << 7)}
def _fcflags_(mn): return bitmask_list(_FC_FLAGS_,mn)

# Std 8.2.4.1.3
# each subtype field bit pos indicates a specfic modification of the base data frame
_DATA_SUBTYPE_FIELDS_ = {'cf-ack':(1 << 0),'cf-poll':(1 << 1),
                         'no-body':(1 << 2),'qos':(1 << 3)}
def datasubtype(mn): return bitmask(_DATA_SUBTYPE_FIELDS_,mn)
def datasubtype_all(mn): return bitmask_list(_DATA_SUBTYPE_FIELDS_,mn)
def datasubtype_get(mn,f):
    try:
        return bitmask_get(_DATA_SUBTYPE_FIELDS_,mn,f)
    except KeyError:
        raise MPDUException("invalid data subtype flag '%s'" % f)

def subtypes(ft,st):
    """ returns the subtype description given the values ft and st """
    if ft == FT_MGMT: return ST_MGMT_TYPES[st]
    elif ft == FT_CTRL: return ST_CTRL_TYPES[st]
    elif ft == FT_DATA: return ST_DATA_TYPES[st]
    else: return 'rsrv'

#### DURATION/ID Std 8.2.4.2 (also see Table 3.3 in CWAP)
# Duration/ID field is 2 bytes and has three functions
#  1. Virtual carrier-sense: value is the NAV timer (i.e. duration)
#  2. Legacy Power MGMT: value is an association id (AID) in PS-Poll frames
#  3. Contention-Free Period: indicates that a PCF process has begun
# Bit    0 - 13| 14| 15| value=
#         0 - 32767|  0| duration
#             0|  0|  1| CFP (fixed value of 32768)
#       1-16383|  0|  1| Reserved
#             0|  1|  1| Reserved
#        1-2007|  1|  1| AID (PS-Poll frames)
#         >2008|  1|  1| Reserved
_DUR_SIG_BITS_ = {'15':(1 << 15), '14':(1 << 14)}
_DUR_CFP_ = 32768
def _duration_(v):
    """ parse duration field v """
    bits = bitmask_list(_DUR_SIG_BITS_,v)
    if not bits['15']: return {'type':'vcs','dur':leastx(15,v)}
    else:
        if not bits['14']:
            if v == _DUR_CFP_: return {'type':'cfp'}
        else:
            x = leastx(13,v)
            if x <= 2007: return {'type':'aid','aid':x}
    return {'type':None,'dur':'rsrv'}

#### ADDRESS Fields Std 8.2.4.3
def _hwaddr_(l):
    """ converts list of unpacked ints to string hw address in lower case hex """
    if len(l) != 6: raise RuntimeError('mac address has length 6')
    return ":".join(['{0:02x}'.format(a) for a in l])

#### SEQUENCE CONTROL Std 8.2.4.4
# Seq. Ctrl is 2 bytes and consists of the follwoing
# Fragment Number (4 bits) number of each fragment of an MSDU/MMPDU
# Sequence Number (12 bits) number of a MSDU, A-MSDU or MMPDU
_SEQCTRL_DIVIDER_ = 4
def _seqctrl_(v): return {'fragno':leastx(_SEQCTRL_DIVIDER_,v),
                          'seqno':mostx(_SEQCTRL_DIVIDER_,v)}

#### QoS CONTROL Std 8.2.4.5
# QoS Ctrl is 2 bytes and consists of five or eight subfields depending on
# the sender and frame subtype
# See Table 8-4 for descriptions

# ACCESS CATEGORY CONSTANTS
QOS_AC_BE_BE = 0
QOS_AC_BK_BK = 1
QOS_AC_BK_NN = 2
QOS_AC_BE_EE = 3
QOS_AC_VI_CL = 4
QOS_AC_VI_VI = 5
QOS_AC_VO_VO = 6
QOS_AC_VO_NC = 7

# least signficant 8 bits
_QOS_FIELDS_ = {'eosp':(1 << 4),'a-msdu':(1 << 7)}
_QOS_TID_END_          = 4 # BITS 0 - 3
_QOS_ACK_POLICY_START_ = 5 # BITS 5-6
_QOS_ACK_POLICY_LEN_   = 2

def _qosctrl_(v):
    """ parse the qos field from the unpacked values v """
    lsb = v[0] # bits 0-7
    msb = v[1] # bits 8-15

    # bits 0-7 are TID (3 bits), EOSP (1 bit), ACK Policy (2 bits and A-MSDU-present(1 bit)
    qos = bitmask_list(_QOS_FIELDS_,lsb)
    qos['tid'] = leastx(_QOS_TID_END_,lsb)
    qos['ack-policy'] = midx(_QOS_ACK_POLICY_START_,_QOS_ACK_POLICY_LEN_,lsb)
    qos['txop'] = msb # bits 8-15 can vary Std Table 8-4
    return qos

# most signficant 8 bits
#                                 |Sent by HC          |Non-AP STA EOSP=0  |Non-AP STA EOSP=1
# --------------------------------|----------------------------------------|----------------
# ST_DATA_QOS_CFPOLL              |TXOP Limit          |                   |
# ST_DATA_QOS_CFACK_CFPOLL        |TXOP Limit          |                   |
# ST_DATA_QOS_DATA_CFACK          |TXOP Limit          |                   |
# ST_DATA_QOS_DATA_CFACK_CFPOLL   |TXOP Limit          |                   |
# ST_DATA_QOS_DATA                |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# ST_DATA_QOS_DATA_CFACK          |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# ST_DATA_QOS_NULL                |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# In Mesh BSS: Mesh Field -> (Mesh Control,Mesh Power Save, RSPI, Reserved
# Othewise Reserved
#
# TXOP Limit:
# TXOP Duration Requested: EOSP bit not set
# AP PS Buffer State:
# Queue Size: sent by non-AP STA with EOSP bit set


# AP PS Buffer State
_QOS_AP_PS_BUFFER_FIELDS = {'rsrv':(1 << 0),'buffer-state-indicated':(1 << 1)}
_QOS_AP_PS_BUFFER_HIGH_PRI_START_ = 2 # BITS 2-3 (corresponds to 10 thru 11)
_QOS_AP_PS_BUFFER_HIGH_PRI_LEN_   = 2
_QOS_AP_PS_BUFFER_AP_BUFF_START_  = 4 # BITS 4-7 (corresponds to 12 thru 15
def _qosapbufferstate_(v):
    """ parse the qos ap ps buffer state """
    apps = bitmask_list(_QOS_FIELDS_,v)
    apps['high-pri'] = midx(_QOS_AP_PS_BUFFER_HIGH_PRI_START_,
                            _QOS_AP_PS_BUFFER_HIGH_PRI_LEN_,v)
    apps['ap-buffered'] = mostx(_QOS_AP_PS_BUFFER_AP_BUFF_START_,v)
    return apps

# Mesh Fields
_QOS_MESH_FIELDS_ = {'mesh-control':(1 << 0),'pwr-save-lvl':(1 << 1),'rspi':(1 << 2)}
_QOS_MESH_RSRV_START_  = 3
def _qosmesh_(v):
    """ parse the qos mesh fields """
    mf = bitmask_list(_QOS_MESH_FIELDS_,v)
    mf['high-pri'] = mostx(_QOS_MESH_RSRV_START_,v)
    return mf

#### HT CONTROL Std 8.2.4.6
# HTC is 4 bytes
_HTC_FIELDS_ = {'lac-rsrv':(1 << 0),
                'lac-trq':(1 << 1),
                'lac-mai-mrq':(1 << 2),
                'ndp-annoucement':(1 << 24),
                'ac-constraint':(1 << 30),
                'rdg-more-ppdu':(1 << 31)}
_HTC_LAC_MAI_MSI_START_      =  3
_HTC_LAC_MAI_MSI_LEN_        =  3
_HTC_LAC_MFSI_START_         =  6
_HTC_LAC_MFSI_LEN_           =  3
_HTC_LAC_MFBASEL_CMD_START_  =  9
_HTC_LAC_MFBASEL_CMD_LEN_    =  3
_HTC_LAC_MFBASEL_DATA_START_ = 12
_HTC_LAC_MFBASEL_DATA_LEN_   =  4
_HTC_CALIBRATION_POS_START_  = 16
_HTC_CALIBRATION_POS_LEN_    =  2
_HTC_CALIBRATION_SEQ_START_  = 18
_HTC_CALIBRATION_SEQ_LEN_    =  2
_HTC_RSRV1_START_            = 20
_HTC_RSRV1_LEN_              =  2
_HTC_CSI_STEERING_START_     = 22
_HTC_CSI_STEERING_LEN_       =  2
_HTC_RSRV2_START_            = 25
_HTC_RSRV2_LEN_              =  5

def _htctrl_(v):
    """
     parse out the htc field from f at offset o, placing values in dict d and
     returning the new offset
    """
    # unpack the 4 octets as a whole and parse out individual components
    htc = bitmask_list(_HTC_FIELDS_,v)
    htc['lac-mai-msi'] = midx(_HTC_LAC_MAI_MSI_START_,_HTC_LAC_MAI_MSI_LEN_,v)
    htc['lac-mfsi'] = midx(_HTC_LAC_MFSI_START_,_HTC_LAC_MFSI_LEN_,v)
    htc['lac-mfbasel-cmd'] = midx(_HTC_LAC_MFBASEL_CMD_START_,
                                  _HTC_LAC_MFBASEL_CMD_LEN_,v)
    htc['lac-mfbasel-data'] = midx(_HTC_LAC_MFBASEL_DATA_START_,
                                   _HTC_LAC_MFBASEL_DATA_LEN_,v)
    htc['calibration-pos'] = midx(_HTC_CALIBRATION_POS_START_,
                                  _HTC_CALIBRATION_POS_LEN_,v)
    htc['calibration-seq'] = midx(_HTC_CALIBRATION_SEQ_START_,
                                  _HTC_CALIBRATION_SEQ_LEN_,v)
    htc['rsrv1'] = midx(_HTC_RSRV1_START_,_HTC_RSRV1_LEN_,v)
    htc['csi-steering'] = midx(_HTC_CSI_STEERING_START_,_HTC_CSI_STEERING_LEN_,v)
    htc['rsrv2'] = midx(_HTC_RSRV2_START_,_HTC_RSRV2_LEN_,v)
    return htc

## FRAME TYPE PARSING

#--> MGMT Frames Std 8.3.3
def _parsemgmt_(f,mac):
    """ parse the mgmt frame f into the mac dict """
    fmt = _S2F_['addr'] + _S2F_['addr'] + _S2F_['seqctrl']
    v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
    mac['addr2'] = _hwaddr_(v[0:6])
    mac['addr3'] = _hwaddr_(v[6:12])
    mac['seqctrl'] = _seqctrl_(v[-1])
    mac['present'].extend(['addr2','addr3','seqctrl'])

    # HTC fields?
    #if mac.flags['o']:
    #    v,o = _unpack_from_(_S2F_['htc'],f,o)
    #    d['htc'] = _htctrl_(v)
    #    mac['present'].append('htc')

    # parse out subtype fixed parameters
    if mac.subtype == ST_MGMT_ASSOC_REQ:
        # cability info, listen interval
        fmt = _S2F_['capability'] + _S2F_['listen-int']
        v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
        mac['fixed-params'] = {'capability':capinfo_all(v[0]),'listen-int':v[1]}
        mac['present'].append('fixed-params')
    elif mac.subtype == ST_MGMT_ASSOC_RESP or mac.subtype == ST_MGMT_REASSOC_RESP:
        # capability info, status code and association id (only uses 14 lsb)
        fmt = _S2F_['capability'] + _S2F_['status-code'] + _S2F_['aid']
        v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
        mac['fixed-params'] = {'capability':capinfo_all(v[0]),
                               'status-code':v[1],
                               'aid':leastx(14,v[2])}
        mac['present'].append('fixed-params')
    elif mac.subtype == ST_MGMT_REASSOC_REQ:
        fmt = _S2F_['capability'] + _S2F_['listen-int'] + _S2F_['addr']
        v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
        mac['fixed-params'] = {'capability':capinfo_all(v[0]),
                               'listen-int':v[1],
                               'current-ap':_hwaddr_(v[2:])}
        mac['present'].append('fixed-params')
    elif mac.subtype == ST_MGMT_PROBE_REQ: pass # all fields are info-elements
    elif mac.subtype == ST_MGMT_TIMING_ADV:
        fmt = _S2F_['timestamp'] + _S2F_['capability']
        v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
        mac['fixed-params'] = {'timestamp':v[0],
                               'capability':capinfo_all(v[1])}
        mac['present'].append('fixed-params')
    elif mac.subtype == ST_MGMT_PROBE_RESP or mac.subtype == ST_MGMT_BEACON:
        fmt = _S2F_['timestamp'] + _S2F_['beacon-int'] + _S2F_['capability']
        v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
        mac['fixed-params'] = {'timestamp':v[0],
                               'beacon-int':v[1]*1024,    # return in microseconds
                               'capability':capinfo_all(v[2])}
        mac['present'].append('fixed-params')
    elif mac.subtype == ST_MGMT_DISASSOC or mac.subtype == ST_MGMT_DEAUTH:
        v,mac['offset'] = _unpack_from_(_S2F_['reason-code'],f,mac['offset'])
        mac['fixed-params'] = {'reason-code':v}
        mac['present'].append('fixed-params')
    elif mac.subtype == ST_MGMT_AUTH:
        fmt = _S2F_['algorithm-no'] + _S2F_['auth-seq'] + _S2F_['status-code']
        v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
        mac['fixed-params'] = {'algorithm-no':v[0],
                               'auth-seq':v[1],
                               'status-code':v[2]}
        mac['present'].append('fixed-params')
    elif mac.subtype == ST_MGMT_ACTION or mac.subtype == ST_MGMT_ACTION_NOACK:
        fmt = _S2F_['category'] + _S2F_['action']
        v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
        mac['fixed-params'] = {'category':v[0],'action':v[1]}
        mac['present'].append('fixed-params')

        # store the action element(s)
        if mac['offset'] < len(f):
            mac['action-el'] = f[mac['offset']:]
            mac['present'].append('action-els')
            mac['offset'] = len(f)
    else:
        # ST_MGMT_ATIM, RSRV_7, RSRV_8 or RSRV_15
        return

    # get information elements if any
    if mac['offset'] < len(f):
        mac['info-elements'] = []
        mac['present'].append('info-elements')
        while mac['offset'] < len(f):
            # info elements have the structure (see Std 8.4.2.1)
            # Element ID|Length|Information
            #          1      1    variable
            # They may contain tags with the same id, so these are appended
            # as a tuple t = (id,val)
            v,mac['offset'] = _unpack_from_("BB",f,mac['offset'])
            info = (v[0],f[mac['offset']:mac['offset']+v[1]])
            mac['offset'] += v[1]

            # for certain tags, further parse
            if info[0] == EID_VEND_SPEC:
                # split into tuple (tag,(oui,value))
                oui = "-".join(['{0:02X}'.format(a) for a in struct.unpack(FMT_BO+'3B',
                                                                           info[1][:3])])
                mac['info-elements'].append((info[0],(oui,info[1][3:])))
            elif info[0] == EID_SUPPORTED_RATES or info[0] == EID_EXTENDED_RATES:
                # split into tuple (tag,listofrates) each rate is Mbps
                rates = []
                for rate in info[1]:
                    rates.append(getrate(struct.unpack(FMT_BO+'B',rate)[0]))
                mac['info-elements'].append((info[0],rates))
            else:
                mac['info-elements'].append(info)

#### MGMT Frame subfields
_CAP_INFO_ = {'ess':(1 << 0),
              'ibss':(1 << 1),
              'cfpollable':(1 << 2),
              'cf-poll-req':(1 << 3),
              'privacy':(1 << 4),
              'short-pre':(1 << 5),
              'pbcc':(1 << 6),
              'ch-agility':(1 << 7),
              'spec-mgmt':(1 << 8),
              'qos':(1 << 9),
              'time-slot':(1 << 10),
              'apsd':(1 << 11),
              'rdo-meas':(1 << 12),
              'dsss-ofdm':(1 << 13),
              'delayed-ba':(1 << 14),
              'immediate-ba':(1 << 15)}
def capinfo(mn): return bitmask(_CAP_INFO_,mn)
def capinfo_all(mn): return bitmask_list(_CAP_INFO_,mn)
def capinfo_get(mn,f):
    try:
        return bitmask_get(_CAP_INFO_,mn,f)
    except KeyError:
        raise MPDUException("invalid data subtype flag '%s'" % f)

# CONSTANTS for action frames Std 8.5.1
SPEC_MGMT_MEAS_REQ  = 0
SPEC_MGMT_MEAS_REP  = 1
SPEC_MGMT_TPC_REQ   = 2
SPEC_MGMT_TPC_REP   = 3
SPEC_MGMT_CH_SWITCH = 4

# CONSTANTS for element ids Std 8.4.2.1
# reserved 17 to 31, 47, 49, 128, 129, 133-136, 143-173, 175-220, 222-255
# undefined 77,103
EID_SSID                    =   0
EID_SUPPORTED_RATES         =   1
EID_FH                      =   2
EID_DSSS                    =   3
EID_CF                      =   4
EID_TIM                     =   5
EID_IBSS                    =   6
EID_COUNTRY                 =   7
EID_HOP_PARAMS              =   8
EID_HOP_TABLE               =   9
EID_REQUEST                 =  10
EID_BSS_LOAD                =  11
EID_EDCA                    =  12
EID_TSPEC                   =  13
EID_TCLAS                   =  14
EID_SCHED                   =  15
EID_CHALLENGE               =  16
EID_PWR_CONSTRAINT          =  32
EID_PWR_CAPABILITY          =  33
EID_TPC_REQ                 =  34
EID_TPC_RPT                 =  35
EID_CHANNELS                =  36
EID_CH_SWITCH               =  37
EID_MEAS_REQ                =  38
EID_MEAS_RPT                =  39
EID_QUIET                   =  40
EID_IBSS_DFS                =  41
EID_ERP                     =  42
EID_TS_DELAY                =  43
EID_TCLAS_PRO               =  44
EID_HT_CAP                  =  45
EID_QOS_CAP                 =  46
EID_RSN                     =  48
EID_EXTENDED_RATES          =  50
EID_AP_CH_RPT               =  51
EID_NEIGHBOR_RPT            =  52
EID_RCPI                    =  53
EID_MDE                     =  54
EID_FAST_BSS                =  55
EID_TO_INT                  =  56
EID_RDE                     =  57
EID_DSE                     =  58
EID_OP_CLASSES              =  59
EID_EXT_CH_SWITCH           =  60
EID_HT_OP                   =  61
EID_SEC_CH_OFFSET           =  62
EID_BSS_AVG_DELAY           =  63
EID_ANTENNA                 =  64
EID_RSNI                    =  65
EID_MEAS_PILOT              =  66
EID_BSS_AVAIL               =  67
EID_BSS_AC_DELAY            =  68
EID_TIME_ADV                =  69
EID_RM_ENABLED              =  70
EID_MUL_BSSID               =  71
EID_20_40_COEXIST           =  72
EID_20_40_INTOLERANT        =  73
EID_OVERLAPPING_BSS         =  74
EID_RIC_DESC                =  75
EID_MGMT_MIC                =  76
EID_EVENT_REQ               =  78
EID_EVENT_RPT               =  79
EID_DIAG_REQ                =  80
EID_DIAG_RPT                =  81
EID_LOCATION                =  82
EID_NONTRANS_BSS            =  83
EID_SSID_LIST               =  84
EID_MULT_BSSID_INDEX        =  85
EID_FMS_DESC                =  86
EID_FMS_REQ                 =  87
EID_FMS_RPT                 =  88
EID_QOS_TRAFFIC_CAP         =  89
EID_BSS_MAX_IDLE            =  90
EID_TFS_REQ                 =  91
EID_TFS_RESP                =  92
EID_WNM_SLEEP               =  93
EID_TIM_REQ                 =  94
EID_TIM_RESP                =  95
EID_COLLOCATED_INTERFERENCE =  96
EID_CH_USAGE                =  97
EID_TIME_ZONE               =  98
EID_DMS_REQ                 =  99
EID_DMS_RESP                = 100
EID_LINK_ID                 = 101
EID_WAKEUP_SCHED            = 102
EID_CH_SWITCH_TIMING        = 104
EID_PTI_CTRL                = 105
EID_TPU_BUFF_STATUS         = 106
EID_INTERNETWORKING         = 107
EID_ADV_PROTOCOL            = 108
EID_EXPEDITED_BW_REQ        = 109
EID_QOS_MAP_SET             = 110
EID_ROAMING_CONS            = 111
EID_EMERGENCY_ALERT_ID      = 112
EID_MESH_CONFIG             = 113
EID_MESH_ID                 = 114
EID_MESH_LINK_METRIC_RPT    = 115
EID_CONGESTION              = 116
EID_MESH_PEERING_MGMT       = 117
EID_MESH_CH_SWITCH_PARAM    = 118
EID_MESH_AWAKE_WIN          = 119
EID_BEACON_TIMING           = 120
EID_MCCAOP_SETUP_REQ        = 121
EID_MCCOAP_SETUP_REP        = 122
EID_MCCAOP_ADV              = 123
EID_MCCAOP_TEARDOWN         = 124
EID_GANN                    = 125
EID_RANN                    = 126
EID_EXT_CAP                 = 127
EID_PREQ                    = 130
EID_PREP                    = 131
EID_PERR                    = 132
EID_PXU                     = 137
EID_PXUC                    = 138
EID_AUTH_MESH_PEER_EXC      = 139
EID_MIC                     = 140
EID_DEST_URI                = 141
EID_UAPSD_COEXIST           = 142
EID_MCCAOP_ADV_OVERVIEW     = 174
EID_VEND_SPEC               = 221

# constants for status codes Std Table 8-37 (see also ieee80211.h)
STATUS_SUCCESS                                =   0
STATUS_UNSPECIFIED_FAILURE                    =   1
STATUS_TLDS_WAKEUP_REJECTED_ALT               =   2
STATUS_TLDS_WAKEUP_REJECTED                   =   3
STATUS_SECURITY_DISABLED                      =   5
STATUS_UNACCEPTABLE_LIFETIME                  =   6
STATUS_NOT_IN_SAME_BSSECTED                   =   7
STATUS_CAPS_MISMATCH                          =  10
STATUS_REASSOC_NO_ASSOC_EXISTS                =  11
STATUS_ASSOC_DENIED_UNSPEC                    =  12
STATUS_AUTH_ALG_NOT_SUPPORTED                 =  13
STATUS_TRANS_SEQ_UNEXPECTED                   =  14
STATUS_CHALLENGE_FAIL                         =  15
STATUS_AUTH_TIMEOUT                           =  16
STATUS_NO_ADDITIONAL_STAS                     =  17
STATUS_BASIC_RATES_MISMATCH                   =  18
STATUS_ASSOC_DENIED_NOSHORTPREAMBLE           =  19
STATUS_ASSOC_DENIED_NOPBCC                    =  20
STATUS_ASSOC_DENIED_NOAGILITY                 =  21
STATUS_ASSOC_DENIED_NOSPECTRUM                =  22
STATUS_ASSOC_REJECTED_BAD_POWER               =  23
STATUS_ASSOC_REJECTED_BAD_SUPP_CHAN           =  24
STATUS_ASSOC_DENIED_NOSHORTTIME               =  25
STATUS_ASSOC_DENIED_NODSSSOFDM                =  26
STATUS_ASSOC_DENIED_NOHTSUPPORT               =  27
STATUS_ROKH_UNREACHABLE                       =  28
STATUS_ASSOC_DENIED_NOPCO                     =  29
STATUS_REFUSED_TEMPORARILY                    =  30
STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION     =  31
STATUS_UNSPECIFIED_QOS                        =  32
STATUS_ASSOC_DENIED_NOBANDWIDTH               =  33
STATUS_ASSOC_DENIED_POOR_CONDITIONS           =  34
STATUS_ASSOC_DENIED_UNSUPP_QOS                =  35
STATUS_REQUEST_DECLINED                       =  37
STATUS_INVALID_PARAMETERS                     =  38
STATUS_REJECTED_WITH_SUGGESTED_CHANGES        =  39
STATUS_INVALID_ELEMENT                        =  40
STATUS_INVALID_GROUP_CIPHER                   =  41
STATUS_INVALID_PAIRWISE_CIPHER                =  42
STATUS_INVALID_AKMP                           =  43
STATUS_UNSUPP_RSNE_VERSION                    =  44
STATUS_INVALID_RSNe_CAP                       =  45
STATUS_CIPHER_SUITE_REJECTED                  =  46
STATUS_REJECTED_FOR_DELAY_PERIOD              =  47
STATUS_DLS_NOT_ALLOWED                        =  48
STATUS_NOT_PRESENT                            =  49
STATUS_NOT_QOS_STA                            =  50
STATUS_ASSOC_DENIED_LISTEN_INT                =  51
STATUS_INVALID_FT_SPEC_MGMT_CNT               =  52
STATUS_INVALID_PMKID                          =  53
STATUS_INVALID_MDE                            =  54
STATUS_INVALID_FTE                            =  55
STATUS_TCLAS_NOT_SUPPORTED                    =  56
STATUS_INSUFFICIENT_TCLAS                     =  57
STATUS_SUGGEST_TRANSISTION                    =  58
STATUS_GAS_ADV_PROTOCOL_NOT_SUPPORTED         =  59
STATUS_NO_OUTSTANDING_GAS_REQUEST             =  60
STATUS_GAS_RESPONSE_NOT_RECEIVED_FROM_SERVER  =  61
STATUS_GAS_QUERY_TIMEOUT                      =  62
STATUS_GAS_QUERY_RESPONSE_TOO_LARGE           =  63
STATUS_REJECTED_HOME_WITH_SUGGESTED_CHANGES   =  64
STATUS_SERVER_UNREACHABLE                     =  65
STATUS_REJECTED_FOR_SSP_PERMISSIONS           =  67
STATUS_NO_UNAUTHENTICATED_ACCESS              =  68
STATUS_INVALID_RSNE_CONTENTS                  =  72
STATUS_UAPSD_COEXIST_NOTSUPPORTED             =  73
STATUS_REQUESTED_UAPSD_COEXIST_NOTSUPPORTED   =  74
STATUS_REQUESTED_UAPSD_INTERVAL_NOTSUPPORTED  =  75
STATUS_ANTI_CLOG_TOKEN_REQUIRED               =  76
STATUS_FCG_NOT_SUPP                           =  77
STATUS_CANNOT_FIND_ALTERNATIVE_TBTT           =  78
STATUS_TRANSMISSION_FAILURE                   =  79
STATUS_REQUESTED_TCLAS_NOT_SUPPORTED          =  80
STATUS_TCLAS_RESOURCES_EXHAUSTED              =  81
STATUS_REJECTED_WITH_SUGGESTED_BSS_TRANSITION =  82
STATUS_REFUSED_EXTERNAL_REASON                =  92
STATUS_REFUSED_AP_OUT_OF_MEMORY               =  93
STATUS_REJECTED_EMER_SERVICES_NOT_SUPPORTED   =  94
STATUS_QUERY_RESPONSE_OUTSTANDING             =  95
STATUS_MCCAOP_RESERVATION_CONFLICT            = 100
STATUS_MAF_LIMIT_EXCEEDED                     = 101
STATUS_MCCA_TRACK_LIMIT_EXCEEDED              = 102

# authentication algorithm numbers Std Table 8-36 (see also ieee80211.h)
AUTH_ALGORITHM_OPEN   =     0
AUTH_ALGORITHM_SHARED =     1
AUTH_ALGORITHM_FAST   =     2
AUTH_ALGORITHM_SAE    =     3
AUTH_ALGORITHM_VENDOR = 63535

# reason code Std Table 8-36
REASON_UNSPECIFIED                    =  1
REASON_PREV_AUTH_NOT_VALID            =  2
REASON_DEAUTH_LEAVING                 =  3
REASON_DISASSOC_DUE_TO_INACTIVITY     =  4
REASON_DISASSOC_AP_BUSY               =  5
REASON_CLASS2_FRAME_FROM_NONAUTH_STA  =  6
REASON_CLASS3_FRAME_FROM_NONASSOC_STA =  7
REASON_DISASSOC_STA_HAS_LEFT          =  8
REASON_STA_REQ_ASSOC_WITHOUT_AUTH     =  9
REASON_DISASSOC_BAD_POWER             = 10
REASON_DISASSOC_BAD_SUPP_CHAN         = 11
REASON_INVALID_IE                     = 13
REASON_MIC_FAILURE                    = 14
REASON_4WAY_HANDSHAKE_TIMEOUT         = 15
REASON_GROUP_KEY_HANDSHAKE_TIMEOUT    = 16
REASON_IE_DIFFERENT                   = 17
REASON_INVALID_GROUP_CIPHER           = 18
REASON_INVALID_PAIRWISE_CIPHER        = 19
REASON_INVALID_AKMP                   = 20
REASON_UNSUPP_RSN_VERSION             = 21
REASON_INVALID_RSN_IE_CAP             = 22
REASON_IEEE8021X_FAILED               = 23
REASON_CIPHER_SUITE_REJECTED          = 24
REASON_TDLS_Dl_TEARDOWN_UNREACHABLE   = 25
REASON_TDLS_DL_TEARDOWN_UNSPECIFIED   = 26
REASON_SSP_REQUEST                    = 27
REASON_NO_SSP_ROAMING_AGREEMENT       = 28
REASON_SSP_CIPHER_SUITE               = 29
REASON_NOT_AUTHORIZED_LOCATION        = 30
REASON_SERVICE_CHANGE_PRECLUDES_TS    = 31
REASON_DISASSOC_UNSPECIFIED_QOS       = 32
REASON_DISASSOC_QAP_NO_BANDWIDTH      = 33
REASON_DISASSOC_LOW_ACK               = 34
REASON_DISASSOC_QAP_EXCEED_TXOP       = 35
REASON_STA_LEAVING                    = 36
REASON_STA_NOT_USING_MECH             = 37
REASON_QSTA_REQUIRE_SETUP             = 38
REASON_QSTA_TIMEOUT                   = 39
REASON_QSTA_CIPHER_NOT_SUPP           = 45
REASON_MESH_PEER_CANCELED             = 52
REASON_MESH_MAX_PEERS                 = 53
REASON_MESH_CONFIG                    = 54
REASON_MESH_CLOSE                     = 55
REASON_MESH_MAX_RETRIES               = 56
REASON_MESH_CONFIRM_TIMEOUT           = 57
REASON_MESH_INVALID_GTK               = 58
REASON_MESH_INCONSISTENT_PARAM        = 59
REASON_MESH_INVALID_SECURITY          = 60
REASON_MESH_PATH_ERROR                = 61
REASON_MESH_PATH_NOFORWARD            = 62
REASON_MESH_PATH_DEST_UNREACHABLE     = 63
REASON_MAC_EXISTS_IN_MBSS             = 64
REASON_MESH_CHAN_REGULATORY           = 65
REASON_MESH_CHAN                      = 66

# action category codes Std Table 8-38
CATEGORY_SPECTRUM_MGMT             =   0
CATEGORY_QOS                       =   1
CATEGORY_DLS                       =   2
CATEGORY_BLOCK_ACK                 =   3
CATEGORY_PUBLIC                    =   4
CATEGORY_HT                        =   7
CATEGORY_SA_QUERY                  =   8
CATEGORY_PROTECTED_DUAL_OF_ACTION  =   9
CATEGORY_TDLS                      =  12
CATEGORY_MESH_ACTION               =  13
CATEGORY_MULTIHOP_ACTION           =  14
CATEGORY_SELF_PROTECTED            =  15
CATEGORY_DMG                       =  16
CATEGORY_WMM                       =  17
CATEGORY_FST                       =  18
CATEGORY_UNPROT_DMG                =  20
CATEGORY_VHT                       =  21
CATEGORY_VENDOR_SPECIFIC_PROTECTED = 126
CATEGORY_VENDOR_SPECIFIC           = 127
# 128 to 255 are error codes

# SUUPORTED RATES/EXTENDED RATES Std 8.4.2.3 and 8.4.2.15

# Std 6.5.5.2 table of rates not contained in the BSSBasicRateSet
# Reading 8.4.2.3 directs to the table in 6.5.5.2 which (see below) relates
# the number in bits 0-6 to 0.5 * times that number which is the same thing
# that happens if MSB is set to 1 ????
_RATE_DIVIDER_ = 7
def getrate(val): return leastx(_RATE_DIVIDER_,val) * 0.5

###--> CTRL Frames Std 8.3.1
def _parsectrl_(f,mac):
    """ parse the control frame f into the mac dict """
    if mac.subtype == ST_CTRL_CTS or mac.subtype == ST_CTRL_ACK: pass # do nothing
    elif mac.subtype in [ST_CTRL_RTS,ST_CTRL_PSPOLL,ST_CTRL_CFEND,ST_CTRL_CFEND_CFACK]:
        # append addr2 and process macaddress
        v,mac['offset'] = _unpack_from_(_S2F_['addr'],f,mac['offset'])
        mac['addr2'] = _hwaddr_(v)
        mac['present'].append('addr2')
    elif mac.subtype == ST_CTRL_BLOCK_ACK_REQ:
        # append addr2,
        v,mac['offset'] = _unpack_from_(_S2F_['addr'],f,mac['offset'])
        mac['addr2'] = _hwaddr_(v)
        # & bar control
        v,mac['offset'] = _unpack_from_(_S2F_['barctrl'],f,mac['offset'])
        mac['barctrl'] = _bactrl_(v)
        mac['present'].extend(['addr2','barctrl'])

        # & bar info field
        if not mac['barctrl']['multi-tid']:
            # for 0 0 Basic BlockAckReq and 0 1 Compressed BlockAckReq the
            # bar info field appears to be the same 8.3.1.8.2 and 8.3.1.8.3, a
            # sequence control
            if not mac['barctrl']['compressed-bm']: mac['barctrl']['type'] = 'basic'
            else: mac['barctrl']['type'] = 'compressed'
            v,mac['offset'] = _unpack_from_(_S2F_['seqctrl'],f,mac['offset'])
            mac['barinfo'] = _seqctrl_(v)
        else:
            if not mac['barctrl']['compressed-bm']:
                # 1 0 -> Reserved
                mac['barctrl']['type'] = 'reserved'
                mac['barinfo'] = {'unparsed':hexlify(f[mac['offset']:])}
                mac['offset'] += len(f[mac['offset']:])
            else:
                # 1 1 -> Multi-tid BlockAckReq Std 8.3.1.8.4 See Figures Std 8-22, 8-23
                mac['barctrl']['type'] = 'multi-tid'
                mac['barinfo'] = {'tids':[]}
                for i in xrange(mac['barctrl']['tid-info'] + 1):
                    v,mac['offset'] = _unpack_from_("HH",f,mac['offset'])
                    mac['barinfo']['tids'].append(_pertid_(v))
    elif mac.subtype == ST_CTRL_BLOCK_ACK:
        # add addr2,
        v,mac['offset'] = _unpack_from_(_S2F_['addr'],f,mac['offset'])
        mac['addr2'] = _hwaddr_(v)
        # & ba control
        v,mac['offset'] = _unpack_from_(_S2F_['bactrl'],f,mac['offset'])
        mac['bactrl'] = _bactrl_(v)
        mac['present'].extend(['addr2','bactrl'])

        # & ba info field
        if not mac['bactrl']['multi-tid']:
            v,mac['offset'] = _unpack_from_(_S2F_['seqctrl'],f,mac['offset'])
            mac['bainfo'] = _seqctrl_(v)
            if not mac['bactrl']['compressed-bm']:
                # 0 0 -> Basic BlockAck 8.3.1.9.2
                mac['bactrl']['type'] = 'basic'
                mac['bainfo']['babitmap'] = hexlify(f[mac['offset']:mac['offset']+128])
                mac['offset'] += 128
            else:
                # 0 1 -> Compressed BlockAck Std 8.3.1.9.3
                mac['bactrl']['type'] = 'compressed'
                mac['bainfo']['babitmap'] = hexlify(f[mac['offset']:mac['offset']+8])
                mac['offset'] += 8
        else:
            if not mac['bactrl']['compressed-bm']:
                # 1 0 -> Reserved
                mac['bactrl']['type'] = 'reserved'
                mac['bainfo'] = {'unparsed':hexlify(f[mac['offset']:])}
            else:
                # 1 1 -> Multi-tid BlockAck Std 8.3.1.9.4 see Std Figure 8-28, 8-23
                mac['bactrl']['type'] = 'multi-tid'
                mac['bainfo'] = {'tids':[]}
                for i in xrange(mac['bactrl']['tid-info'] + 1):
                    v,mac['offset'] = _unpack_from_("HH",f,mac['offset'])
                    pt = _pertid_(v)
                    pt['babitmap'] = hexlify(f[mac['offset']:mac['offset']+8])
                    mac['bainfo']['tids'].append(pt)
                    mac['offset'] += 8
    elif mac.subtype == ST_CTRL_WRAPPER:
        # Std 8.3.1.10, carriedframectrl is a Frame Control
        v,mac['offset'] = _unpack_from_(_S2F_['framectrl'],f,mac['offset'])
        mac['carriedframectrl'] = v
        v,mac['offset'] = _unpack_from_(_S2F_['htc'],f,mac['offset'])
        mac['htc'] = v
        mac['carriedframe'] = hexlify(f[mac['offset']:])
        mac['offset'] += len(f[mac['offset']:])
        mac['present'].extend(['carriedframectrl','htc','carriedframe'])
    else:
        raise MPDUException("Unknown subtype in CTRL frame %d" % mac.subtype)

#### Control Frame subfields

#--> Block Ack request Std 8.3.1.8
# BA and BAR Ack Policy|Multi-TID|Compressed BM|Reserved|TID_INFO
#                    B0|       B1|           B2|  B3-B11| B12-B15
# for the ba nad bar information see Std Table 8.16
_BACTRL_ = {'ackpolicy':(1 << 0),'multi-tid':(1 << 1),'compressed-bm':(1 << 2)}
_BACTRL_RSRV_START_     =  3
_BACTRL_RSRV_LEN_       =  9
_BACTRL_TID_INFO_START_ = 12
def _bactrl_(v):
    """ parses the ba/bar control """
    bc = bitmask_list(_BACTRL_,v)
    bc['rsrv'] = midx(_BACTRL_RSRV_START_,_BACTRL_RSRV_LEN_,v)
    bc['tid-info'] = mostx(_BACTRL_TID_INFO_START_,v)
    return bc

#--> Per TID info subfield Std Fig 8-22 and 8-23
_BACTRL_PERTID_DIVIDER_ = 12
_BACTRL_MULTITID_DIVIDER_ = 12
def _pertid_(v):
    """ parses the per tid info and seq control """
    pti = _seqctrl_(v[1])
    pti['pertid-rsrv'] = leastx(_BACTRL_PERTID_DIVIDER_,v[0])
    pti['pertid-tid'] = mostx(_BACTRL_PERTID_DIVIDER_,v[0])
    return pti

#--> DATA Frames Std 8.3.2
def _parsedata_(f,mac):
    """ parse the data frame f into the mac dict """
    # addr2, addr3 & seqctrl are always present in data Std Figure 8-30
    fmt = _S2F_['addr'] + _S2F_['addr'] + _S2F_['seqctrl']
    v,mac['offset'] = _unpack_from_(fmt,f,mac['offset'])
    mac['addr2'] = _hwaddr_(v[0:6])
    mac['addr3'] = _hwaddr_(v[6:12])
    mac['seqctrl'] = _seqctrl_(v[-1])
    mac['present'].extend(['addr2','addr3','seqctrl'])

    # fourth address?
    if mac.flags['td'] and mac.flags['fd']:
        v,mac['offset'] = _unpack_from_(_S2F_['addr'],f,mac['offset'])
        mac['addr4'] = _hwaddr_(v)
        mac['present'].append('addr4')

    # QoS field?
    if ST_DATA_QOS_DATA <= mac.subtype <= ST_DATA_QOS_CFACK_CFPOLL:
        v,mac['offset'] = _unpack_from_(_S2F_['qos'],f,mac['offset'])
        mac['qos'] = _qosctrl_(v)
        mac['present'].append('qos')

        # HTC fields?
        #if mac.flags['o']:
        #    v,mac['offset'] = _unpack_from_(_S2F_['htc'],f,mac['offset'])
        #    mac['htc'] = _htctrl_(v)
        #    mac['present'].append('htc')

#### ENCRYPTION (see Chapter 11 Std)

#### WEP Std 11.2.2.2
# <MAC HDR>|IV|DATA|ICV|FCS
# bytes var| 4| >=1|  4|  4
# where the IV is defined:
# Init Vector|  Pad | Key ID
# bits     24| 6bits| 2 bits
_WEP_IV_LEN_  = 4
_WEP_ICV_LEN_ = 4
_WEP_IV_KEY_START_ = 6
def _wep_(f,mac):
    """ parse wep data from frame f into mac dict """
    keyid = struct.unpack_from(FMT_BO+_S2F_['wep-keyid'],f,
                               mac['offset']+_WEP_IV_LEN_-1)[0]
    mac['l3-crypt'] = {'type':'wep',
                       'iv':hexlify(f[mac['offset']:mac['offset']+_WEP_IV_LEN_]),
                       'key-id':mostx(_WEP_IV_KEY_START_,keyid),
                       'icv':hexlify(f[-_WEP_ICV_LEN_:])}
    mac['offset'] += _WEP_IV_LEN_
    mac['stripped'] += _WEP_ICV_LEN_

#### TKIP Std 11.4.2.1
# <MAC HDR>|IV|ExtIV|DATA|MIC|ICV|FCS
# bytes var| 4|    4| >=1|  8|  4|  4
# where the IV is defined
#   TSC1|WEPSeed|TSC0|RSRV|EXT IV|KeyID
# bits 8|      8|   8|   4|     1|    3
# and the extended iv is defined as
#   TSC2|TSC3|TSC4|TSC5
# bits 8|   8|   8|   8
_TKIP_TSC1_BYTE_      = 0
_TKIP_WEPSEED_BYTE_   = 1
_TKIP_TSC0_BYTE_      = 2
_TKIP_KEY_BYTE_       = 3
_TKIP_EXT_IV_         = 5
_TKIP_EXT_IV_LEN_     = 1
_TKIP_TSC2_BYTE_      = 4
_TKIP_TSC3_BYTE_      = 5
_TKIP_TSC4_BYTE_      = 6
_TKIP_TSC5_BYTE_      = 7
_TKIP_IV_LEN_         = 8
_TKIP_MIC_LEN_        = 8
_TKIP_ICV_LEN_        = 4
def _tkip_(f,mac):
    """ parse tkip data from frame f into mac dict """
    keyid = struct.unpack_from(FMT_BO+'B',f,mac['offset']+_TKIP_KEY_BYTE_)[0]
    mac['l3-crypt'] = {'type':'tkip',
                       'iv':{'tsc1':hexlify(f[mac['offset']+_TKIP_TSC1_BYTE_]),
                             'wep-seed':hexlify(f[mac['offset']+_TKIP_WEPSEED_BYTE_]),
                             'tsc0':hexlify(f[mac['offset']+_TKIP_TSC0_BYTE_]),
                             'key-id':{'rsrv':leastx(_TKIP_EXT_IV_,keyid),
                                       'ext-iv':midx(_TKIP_EXT_IV_,_TKIP_EXT_IV_LEN_,keyid),
                                       'key-id':mostx(_TKIP_EXT_IV_+_TKIP_EXT_IV_LEN_,keyid)}},
                       'ext-iv':{'tsc2':hexlify(f[mac['offset']+_TKIP_TSC2_BYTE_]),
                                 'tsc3':hexlify(f[mac['offset']+_TKIP_TSC3_BYTE_]),
                                 'tsc4':hexlify(f[mac['offset']+_TKIP_TSC4_BYTE_]),
                                 'tsc5':hexlify(f[mac['offset']+_TKIP_TSC5_BYTE_])},
                       'mic':hexlify(f[-(_TKIP_MIC_LEN_ + _TKIP_ICV_LEN_):-_TKIP_ICV_LEN_]),
                       'icv':hexlify(f[-_TKIP_ICV_LEN_:])}
    mac['offset'] += _TKIP_IV_LEN_
    mac['stripped'] += _TKIP_MIC_LEN_ + _TKIP_ICV_LEN_

#### CCMP Std 11.4.3.2
# <MAC HDR>|CCMP HDR|DATA|MIC|FCS
# bytes var|       8| >=1|  8|  4
# where the CCMP Header is defined
#    PN0|PN1|RSRV|RSRV|EXT IV|KeyID|PN2|PN3|PN4|PN5
# bits 8|  8|   8|   5|     1|    2|  8|  8|  8|  8
_CCMP_PN0_BYTE_   = 0
_CCMP_PN1_BYTE_   = 1
_CCMP_RSRV_BYTE_  = 2
_CCMP_KEY_BYTE_   = 3
_CCMP_EXT_IV_     = 5
_CCMP_EXT_IV_LEN_ = 1
_CCMP_PN2_BYTE_   = 4
_CCMP_PN3_BYTE_   = 5
_CCMP_PN4_BYTE_   = 6
_CCMP_PN5_BYTE_   = 7
_CCMP_IV_LEN_     = 8
_CCMP_MIC_LEN_    = 8
def _ccmp_(f,mac):
    """ parse tkip data from frame f into mac dict """
    keyid = struct.unpack_from(FMT_BO+'B',f,mac['offset']+_CCMP_KEY_BYTE_)[0]

    mac['l3-crypt'] = {'type':'ccmp',
                       'pn0':hexlify(f[mac['offset']+_CCMP_PN0_BYTE_]),
                       'pn1':hexlify(f[mac['offset']+_CCMP_PN1_BYTE_]),
                       'rsrv':hexlify(f[mac['offset']+_CCMP_RSRV_BYTE_]),
                       'key-id':{'rsrv':leastx(_CCMP_EXT_IV_,keyid),
                                 'ext-iv':midx(_CCMP_EXT_IV_,_CCMP_EXT_IV_LEN_,keyid),
                                 'key-id':mostx(_CCMP_EXT_IV_+_CCMP_EXT_IV_LEN_,keyid)},
                       'pn2':hexlify(f[mac['offset']+_CCMP_PN2_BYTE_]),
                       'pn3':hexlify(f[mac['offset']+_CCMP_PN3_BYTE_]),
                       'pn4':hexlify(f[mac['offset']+_CCMP_PN4_BYTE_]),
                       'pn5':hexlify(f[mac['offset']+_CCMP_PN0_BYTE_]),
                       'mic':hexlify(f[-_CCMP_MIC_LEN_:])}

    mac['offset'] += _CCMP_IV_LEN_
    mac['stripped'] += _CCMP_MIC_LEN_

#### HELPERS

def _unpack_from_(fmt,b,o):
    """
     unpack data from the buffer b given the format specifier fmt starting at o &
     returns the unpacked data and the new offset
    """
    try:
        vs = struct.unpack_from(FMT_BO+fmt,b,o)
        if len(vs) == 1: vs = vs[0]
        return vs,o+struct.calcsize(fmt)
    except struct.error as e:
        raise MPDUException('Error unpacking: %s' % e)
