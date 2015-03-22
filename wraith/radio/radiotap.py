#!/usr/bin/env python

""" radiotap.py: radiotap frame (www.radiotap.org) parsing

Parse radiotap frames (radiotap.org defined fields) only. Will not parse correctly
if extended fields are present prior to defined fields. It is recommended not 
to import * as it may cause conflicts with other modules
"""
__name__ = 'radiotap'
__license__ = 'GPL v3.0'
__version__ = '0.0.4'
__date__ = 'August 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import struct
from wraith.utils.bits import bitmask, bitmask_list, bitmask_get

class RadiotapException(Exception): pass

FMT_BO = "@" # struct format byte order specifier

def parse(f):
    """
     parses the radiotap in f returning a dict d where d will always have
      key->value pairs for:
       vers: the radiotap version
       sz: bytes of radiotap header
       present: an ordered list of fields present in this frame
     and key->value pairs for each field in present
     NOTE: tried unpacking individually (concise code) but it failed to align
     the individual fields
    """
    # parse header and present flags
    (v,l,p) = header(f)
    if v != 0 or len(f) < l: raise RadiotapException("Invalid frame")
    flags = present_list(p)

    # for the flags that are true, add a format specifier and unpack
    ufmt = FMT_BO # format specified
    fs = []       # list of flags
    ps = []       # ordered list of present fields
    for (flag,fmt) in _P2F_:
        if not flags[flag]: continue
        ufmt += fmt
        fs.append((flag,len(fmt)))
        ps.append(flag)
    vs = list(struct.unpack_from(ufmt,f,_HDR_SZ_))

    # compile fields and values into dict
    fields = {'vers':v,'sz':l,'present':ps}
    for (f,lF) in fs:
        if lF == 1: fields[f] = vs.pop(0)
        else:
            fields[f] = []
            while lF:
                fields[f].append(vs.pop(0))
                lF -= 1
    return fields

#--> RADIO TAP HEADER <-- http://www.radiotap.org/Radiotap
# Note: Radiotap fields are in little-endian byte-order.
# (u8)  it_version: always 0, for the foreseeable future
# (u8)  it_pad:     padding
# (u16) it_len:     length of radio tap including this header
# (u32) it_present: bitmask of which fields are present. Additional extensions can 
#                   be made by setting bit 31
_HDR_ = FMT_BO + "BxHI"
_HDR_SZ_ = struct.calcsize(_HDR_)
def header(f):
    """  parse/return tuple = (version,length,present) from frame f """
    try:
        return struct.unpack(_HDR_,f[:_HDR_SZ_])
    except struct.error:
        raise RadiotapException("invalid frame")

_VER_ =  FMT_BO + "B"
_VER_SZ_ = struct.calcsize(_VER_)
def version(f):
    """
     parse/return it_version of the radio tap frame in frame f
     NOTE: does throw exception on invalid version
    """
    try:
        return struct.unpack(_VER_,f[:_VER_SZ_])[0]
    except struct.error:
        raise RadiotapException("invalid frame")

_LEN_ =  FMT_BO + "BxH"
_LEN_SZ_ = struct.calcsize(_LEN_)
def length(f):
    """
     parse/return the it_len of the radio tap frame (if valid) in frame f
     NOTE: this will raise an exception if, the header does not have a vers,
      length and present flags and if the v is not 0
    """
    try:
        (v,l) = struct.unpack(_LEN_,f[:_LEN_SZ_])
    except struct.error:
        raise RadiotapException("invalid frame")
    if v: raise RadiotapException("invalid vers. %d" % v)
    return l

def pflags(f):
    """
     parse/return the it_present of the radio tap frame (if valid) in frame f
     NOTE: this will raise an exception if, the header does not have a vers,
      length and present flags and if the v is not 0
    """    
    try:
        (v,l,p) = struct.unpack(_HDR_,f[:_HDR_SZ_])
    except struct.error:
        raise RadiotapException("frame")
    if v: raise RadiotapException("invalid vers. %d" % v)
    return p
          
#--> IT_PRESENT FLAGS <-- (see description of each present flag)
# FLAG       Bit Number   Unit  Description
# TSFT                0    u64  Value in microseconds of the MAC's 64-bit 802.11 Time 
#                               Synchronization Function timer when the first bit of the 
#                               MPDU arrived at the MAC. For received frames only.
# Flags               1     u8  Properties of transmitted and received frames, bitmask
# Rate                2     u8  TX/RX data rate by 500Kbps
# Channel             3  u16*2  Tx/Rx frequency in MHz, followed by flags.
# FHSS                4   u8*2  The hop set and pattern for frequency-hopping radios.
# Antenna signal      5     s8  RF signal power at the antenna. This field contains 
#                               a single signed 8-bit value, which indicates the RF 
#                               signal power at the antenna, in decibels difference 
#                               from 1mW.
# Antenna noise       6     s8  RF noise power at the antenna. This field contains 
#                               a single signed 8-bit value, which indicates the RF 
#                               signal power at the antenna, in decibels difference 
#                               from 1mW.
# Lock quality        7    u16  Quality of Barker code lock. Unitless. Monotonically 
#                               nondecreasing with "better" lock strength. Called 
#                               "Signal Quality" in datasheets
# TX attenuation      8    u16  Transmit power expressed as unitless distance from 
#                               max power set at factory calibration. 0 is max 
#                               power. Monotonically nondecreasing with lower power 
#                               levels.
# db TX attenuation   9    u16  Transmit power expressed as decibel distance from 
#                               max power set at factory calibration. 0 is max power. 
#                               Monotonically nondecreasing with lower power levels.
# dBm TX power       10     s8  Transmit power expressed as dBm. This is the absolute 
#                               power level measured at the antenna port.
# Antenna            11     u8  Rx/Tx antenna for this packet, 1st antenna 0.
# db antenna signal  12     u8  RF signal power at the antenna, decibel difference 
#                               from an arbitrary, fixed reference.
# db antenna noise   13     u8  RF noise power at the antenna, decibel difference 
#                               from an arbitrary, fixed reference.
# RX flags           14     u16 bitmask, properties of received frames
# TX flags           15         (not defined yet in radiotap)
# RTS retries        16         (not defined yet in radiotap)
# Data retries       17         (not defined yet in radiotap)
# MCS                19    u8*3 Modulation and Coding Scheme, a known field, flags 
#                               and mcs field (mcs rate index) as in IEEE_802.11n-2009
#                               Wireshark calls this HT
# A-MPDU             20       * u32 reference number, u16 flags, u8 delimiter CRC 
#                               value, u8 reserved indicates that the frame was 
#                               received as part of an a-MPDU.
# VHT                21       * u16 known, u8 flags, u8 bandwidth, u8 mcs_nss[4], 
#                               u8 coding, u8 group_id, u16 partial_aid
# Radiotap Namespace 29         valid in every it_present bitmask
# Vendor Namespace   30         valid in every it_present bitmask
# Extended           31         extended

# _P2F_ list of tuples, (flag,format string)
_P2F_ = [('tsft','Q'),
         ('flags','B'),
         ('rate','B'),
         ('channel','HH'),
         ('fhss','BB'),
         ('antsignal','b'),
         ('antnoise','b'),
         ('lock_quality','H'),
         ('tx_attenuation','H'),
         ('db_tx_attenuation','H'),
         ('dbm_tx_power','b'),
         ('antenna','B'),
         ('db_antsignal','B'),
         ('db_antnoise','B'),
         ('rx_flags','H'),
         ('mcs','BBB'),
         ('a-mpdu','LHBB'),
         ('vht','HBBBBBH')]
# _PRESENT_ present flags bitmask
_PRESENT_ = {'tsft':(1 << 0),
             'flags':(1 << 1),
             'rate':(1 << 2),
             'channel':(1 << 3),
             'fhss':(1 << 4),
             'antsignal':(1 << 5),
             'antnoise':(1 << 6),
             'lock_quality':(1 << 7),
             'tx_attenuation':(1 << 8),
             'db_tx_attenuation':(1 << 9),
             'dbm_tx_power':(1 << 10),
             'antenna':(1 << 11),
             'db_antsignal':(1 << 12),
             'db_antnoise':(1 << 13),
             'rx_flags':(1 << 14),
             'mcs':(1 << 19),
             'a-mpdu':(1 << 20),
             'vht':(1 << 21),
             'radiotap_namespace':(1 << 29),
             'vendor_namespace':(1 << 30),
             'ext':(1 << 31)}
def present(mn): return bitmask(_PRESENT_,mn)
def present_list(mn): return bitmask_list(_PRESENT_,mn)
def present_get(mn,f):
    try:
        return bitmask_get(_PRESENT_,mn,f)
    except KeyError:
        raise RadiotapException("Invalid present flag '%s'" % f)

# --> Flags <-- http://www.radiotap.org/defined-fields/Flags
# cfp Sent/Received during CFP
# short Sent/Received during short preamble
# wep Sent/Received with WEP encryption
# frag Sent/Received with fragmentation
# fcs Includes FCS
# pad Frame has padding betw/ 802.11 header and payload
# fail Frame failed fcs check
# short Frame used short guard interval (currently unspecfied but used)
_FLAGS_ = {'cfp':0x01,'short':0x02,'wep':0x04,'frag':0x08,'fcs':0x10,
           'pad':0x20,'fail':0x40,'shortgi':0x80}
def flags(mn): return bitmask(_FLAGS_,mn)
def flags_list(mn): return bitmask_list(_FLAGS_,mn)
def flags_get(mn,f):
    try:
        return bitmask_get(_FLAGS_,mn,f)
    except KeyError:
        raise RadiotapException("invalid flag '%s'" % f)
        
# --> CHANNEL FLAGS <-- http://www.radiotap.org/defined-fields/Channel
# turbo Turbo Channel
# cck CCK Channel
# ofdm OFDM Channel
# ism 2 GHz Channel
# unii 5 GHz Channel
# passive Only Passive scan allowed
# dcck Dyanamic CCK-OFDM channel
# gfsk GFSK Channel (FHS PHY)
_CHANNEL_FLAGS_ = {'turbo':0x0010,'cck':0x0020,'ofdm':0x0040,'ism':0x0080,
                   'unii':0x0100,'passive':0x0200,'dcck':0x0400,'gfsk':0x0800,}
def chflags(mn): return bitmask(_CHANNEL_FLAGS_,mn)
def chflags_list(mn): return bitmask_list(_CHANNEL_FLAGS_,mn)
def chflags_get(mn,f):
    try:
        return bitmask_get(_CHANNEL_FLAGS_,mn,f)
    except KeyError:
        raise RadiotapException("invalid channel flag '%s'" % f)

# --> RX Flags <-- http://www.radiotap.org/defined-fields/RX%20flags
# crc PLCP CRC check failed
_RX_FLAGS_= {'crc':0x0002}
def rxflags(mn): return bitmask(_RX_FLAGS_,mn)
def rxflags_list(mn): return bitmask_list(_RX_FLAGS_,mn)
def rxflags_get(mn,f):
    try:
        return bitmask_get(_RX_FLAGS_,mn,f)
    except KeyError:
        raise RadiotapException("invalid RX flag '%s'" % f) 

# --> MCS Known <-- http://www.radiotap.org/defined-fields/MCS
# bw Bandwidth
# mcs MCS index known
# gi Guard interval
# ht HT format
# fec FEC Type
# stbc STBC Known
# nessk Number of extension spatial streams known
# nessd  bit 1 (MSB) of Number of extension spatial streams
_MCS_KNOWN_ = {'bw':0x01,'mcs':0x02,'gi':0x04,'ht':0x08,'fec':0x10,'stbc':0x20,
               'nessk':0x40,'nessd':0x80}
def mcsknown(mn): return bitmask(_MCS_KNOWN_,mn)
def mcsknown_list(mn): return bitmask_list(_MCS_KNOWN_,mn)
def mcsknown_get(mn,f):
    try:
        return bitmask_get(_MCS_KNOWN_,mn,f)
    except KeyError:
        raise RadiotapException("invalid MCS Known field '%s'" % f)

# --> MCS Flags <-- http://www.radiotap.org/defined-fields/MCS
# bw Bandwidth (0: 20, 1: 40, 2: 20L, 3: 20U) ?
# gi Guard Interval (0: long GI, 1: Short GI)
# ht HT Format (0: mixed, 1: greenfield)
# fec FEC Type (0: BCC,1: LDPC)
# stbc # of STBC streams
# ness Bit 0 LSB of # of extension spatial streams 
MCS_BW_20           = 0
MCS_BW_40           = 1
MCS_BW_20L          = 2
MCS_BW_20U          = 3
MCS_GI_LONG         = 0
MCS_GI_SHORT        = 1
MCS_HT_FORMAT_MIX   = 0
MCS_HT_FORMAT_GREEN = 1
MCS_FEC_TYPE_BCC    = 0
MCS_FEC_TYPE_LDPC   = 1
_MCS_FLAGS_ = {'bw':0x03,'gi':0x04,'ht':0x08,'fec':0x10,'stbc':0x60,'ness':0x80}
def mcsflags_params(kn,fn):
    """
     given the flags number fn and known number kn returns the corresponding
     values for all known flags 
    """
    return {n:_MCS_FLAGS_[n] & fn for n in _MCS_FLAGS_ if n in mcsknown(kn)}


# --> A-MPDU Flags <-- http://www.radiotap.org/defined-fields/A-MPDU%20status
# nolen Driver reports 0-length subframes
# nolensub Frame is a 0-length subframe (only valid if nolen is set)
# known last subframe is known (should be set for all subframes in an A-MPDU)
# last this is the last subframe
# err Delimter CRC error
# crc delimiter CRC value known: the delimiter CRC value field is valid
_AMPDU_FLAGS_ = {'nolen':0x0001,'nolensub':0x0002,'known':0x0004,
                 'last':0x0008,'err':0x0010,'crc':0x0020}
def ampduflags(mn): return bitmask(_AMPDU_FLAGS_,mn)
def ampduflags_list(mn): return bitmask_list(_AMPDU_FLAGS_,mn)
def ampduflags_get(mn,f):
    try:
        return bitmask_get(_AMPDU_FLAGS_,mn,f)
    except KeyError:
        raise RadiotapException("invalid A-MPDU flag '%s'" % f)
        
# --> VHT Known <-- http://www.radiotap.org/defined-fields/VHT
# stbc STBC known
# txop TXOP_PS_NOT_ALLOWED known
# gi Guard Interval
# short Short GI NYSI disambiguation known
# ldpc LDPC extra OFDM symbol known
# beam Beamformed known
# bw Bandwidth known
# gid Group ID known
# paid Partial AID known
_VHT_KNOWN_ = {'stbc':0x0001,'txop':0x0002,'gi':0x0004,'short':0x0008,'ldpc':0x0010,
               'beam':0x0020,'bw':0x0040,'gid':0x0080,'paid':0x0100}
def vhtknown(mn): return bitmask(_VHT_KNOWN_,mn)
def vhtknown_list(mn): return bitmask_list(_VHT_KNOWN_,mn)
def vhtknown_get(mn,f):
    try:
        return bitmask_get(_VHT_KNOWN_,mn,f)
    except KeyError:
        raise RadiotapException("invalid VHT Known field '%s'" % f)

# --> VHT Flags <-- http://www.radiotap.org/defined-fields/VHT
# stbc Space-Time Block Coding (Set to 0 if no spatial streams of any user has STBC.
#                               Set to 1 if all spatial streams of all users have STBC.
# txop TXOP_PS_NOT_ALLOWED known Valid only for AP transmitters. Set to 0 if STAs 
#      may doze during TXOP. Set to 1 if STAs may not doze during TXOP or trans
#      is non-AP.
# gi Guard Interval Set to 0 for long GI. Set to 1 for short GI.
# short Short GI NYSI disambiguation Valid only if short GI is used. Set to 0 if 
#       NSYM mod 10 != 9 or short GI not used. Set to 1 if NSYM mod 10 = 9.
# ldpc LDPC extra OFDM symbol Set to 1 if >= 1 users are using LDPC and the encoding 
#      process resulted in extra OFDM symbol(s). Set to 0 otherwise
# beam Beamformed Valid for SU PPDUs only
_VHT_FLAGS_ = {'stbc':0x01,'txop':0x02,'gi':0x04,'short':0x08,'ldpc':0x10,'beam':0x20}        
def vhtflags_params(kn,fn):
    """
     given the flags number fn and known number kn returns the corresponding
     values for all known flags 
    """
    return {name:_VHT_FLAGS_[name] & fn for name in _VHT_FLAGS_ if name in vhtknown(kn)}    

# --> VHT Coding <-- http://www.radiotap.org/defined-fields/VHT
# c0 coding for user 0 Set to 0 for BCC. Set to 1 for LDPC
# c1 coding for user 1 Set to 0 for BCC. Set to 1 for LDPC
# c2 coding for user 2 Set to 0 for BCC. Set to 1 for LDPC
# c3 coding for user 3 Set to 0 for BCC. Set to 1 for LDPC
_VHT_CODING_ = {'c0':0x01,'c1':0x02,'c2':0x04,'c3':0x08}
def vhtcoding(mn): return bitmask(_VHT_CODING_,mn)
def vhtcoding_list(mn): return bitmask_list(_VHT_CODING_,mn)
def vhtcoding_get(mn,f):
    try:
        return bitmask_get(_VHT_CODING_,mn,f)
    except KeyError:
        raise RadiotapException("invalid VHT Coding flag '%s'" % f) 

