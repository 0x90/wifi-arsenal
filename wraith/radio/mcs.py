#!/usr/bin/env python

""" mcs.py: mcs index functions 

NOTE: does not support VHT/802.11ac
"""
__name__ = 'mcs'
__license__ = 'GPL v3.0'
__version__ = '0.0.1'
__date__ = 'August 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

# modulation and coding rate
MCS_HT_INDEX = ["BPSK 1/2",
                "QPSK 1/2",
                "QPSK 3/4",
                "16-QAM 1/2",
                "16-QAM 3/4",
                "64-QAM 2/3",
                "64-QAM 3/4",
                "64-QAM 5/6"]

# mcs rates
MCS_HT_RATES = [{20:{0:6.5,1:7.2},40:{0:13.5,1:15}},
                {20:{0:13,1:14.4},40:{0:27,1:30}},
                {20:{0:19.5,1:21.7},40:{0:40.5,1:45}},
                {20:{0:26,1:28.9},40:{0:54,1:60}},
                {20:{0:39,1:43.3},40:{0:81,1:90}},
                {20:{0:52,1:57.8},40:{0:108,1:120}},
                {20:{0:58.5,1:65},40:{0:121.5,1:135}},
                {20:{0:65,1:72.2},40:{0:135,1:150}},
                {20:{0:13,1:14.4},40:{0:27,1:15}},
                {20:{0:26,1:28.9},40:{0:54,1:30}},
                {20:{0:39,1:43.3},40:{0:81,1:45}},
                {20:{0:52,1:57.8},40:{0:108,1:60}},
                {20:{0:78,1:86.7},40:{0:162,1:90}},
                {20:{0:104,1:115.6},40:{0:216,1:120}},
                {20:{0:117,1:130.3},40:{0:243,1:135}},
                {20:{0:130,1:144.4},40:{0:270,1:150}},
                {20:{0:19.5,1:21.7},40:{0:40.5,1:45}},
                {20:{0:39,1:43.3},40:{0:81,1:90}},
                {20:{0:58.5,1:65},40:{0:121.5,1:135}},
                {20:{0:78,1:86.7},40:{0:162,1:180}},
                {20:{0:117,1:130},40:{0:243,1:270}},
                {20:{0:156,1:173.3},40:{0:324,1:360}},
                {20:{0:175.5,1:195},40:{0:364.5,1:405}},
                {20:{0:195,1:216.7},40:{0:405,1:450}},
                {20:{0:26,1:28.9},40:{0:54,1:60}},
                {20:{0:52,1:57.8},40:{0:108,1:120}},
                {20:{0:78,1:86.7},40:{0:162,1:180}},
                {20:{0:104,1:115.6},40:{0:216,1:240}},
                {20:{0:156,1:173.3},40:{0:324,1:360}},
                {20:{0:208,1:231.1},40:{0:432,1:480}},
                {20:{0:234,1:260},40:{0:486,1:540}},
                {20:{0:260,1:288.9},40:{0:540,1:600}}]

def mcs_coding(i):
    """
     given the mcs index i, returns a tuple (m=modulation & coding rate,s= # of 
     spatial streams)
    """
    if i < 0 or i > 31: raise ValueError("mcs index '%d' must be 0 <= i <= 32" % i)
    (m,n) = divmod(i,8)
    return MCS_HT_INDEX[n],m+1

def mcs_rate(i,w,gi):
    """
     given the mcs index i, channel width w and guard interval (0 for short, 1 
     for long), returns the data rate
    """
    if i < 0 or i > 31: raise ValueError("mcs index '%d' must be 0 <= i <= 32" % i)
    if not(w == 20 or w == 40): raise ValueError("mcs width '%d' must be 20 or 40" % w)
    if gi < 0 or gi > 1: raise ValueError("mcs guard interval '%d' must be 0:short or 1:long" % gi)
    return MCS_HT_RATES[i][w][gi]

def mcs_width(i,dr):
    """
     given mcs index i & data rate dr, returns channel width and guard interval
    """
    if i < 0 or i > 31: raise ValueError("mcs index '%d' must be 0 <= i <= 32" % i)
    for w in MCS_HT_RATES[i]:
        for gi in MCS_HT_RATES[i][w]:
            if MCS_HT_RATES[i][w][gi] == dr:
                return w,gi
    return None

