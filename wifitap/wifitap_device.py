########################################
#
# Copyright (C) 2011 Daniel Smith <viscous.liquid@gmail.com>
# Copyright (C) 2005 Cedric Blancher <sid@rstack.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################

import os,sys,atexit,struct,re,string
from fcntl import ioctl

class WifiTapDevice:
    TUN_CTL     = '/dev/net/tun'
    TUN_SET_IFF = 0x400454ca
    IFF_TAP     = 0x0002

    def __init__(self):
        self.__opened__ = False
        self.inface = 'wlan0'
        self.outface = 'wlan0'
        self.bssid = ''
        self.smac = ''
        self.has_wep = False
        self.wepkey = ''
        self.keyid = 0
        self.debug = False
        self.verb = False

        # Radiotap parameters for injection
        self.rate = None        # Legacy Rate
        self.power = None       # Tx Power
        self.tx_flags = None    # Tx Flags
        self.retries = None     # Data Retries
        self.mcs = None         # N Rate (MCS index)
        self.hgi = False        # HT Guard Interval 

    def open(self, name_format=''):
        if name_format == '':
            name_format = 'wj%d'
        elif name_format.endswith('%d'):
            name_format = name_format
        else:
            name_format = name_format + '%d'

        self.__fd__ = os.open(self.TUN_CTL, os.O_RDWR)
        ifs = ioctl(self.__fd__, self.TUN_SET_IFF,
                struct.pack("16sH", name_format, self.IFF_TAP))
        self.name = ifs[:16].strip("\x00")

        self.__opened__ = True
        atexit.register(self.close)

    def fileno(self):
        if self.__opened__:
            return self.__fd__
        else:
            return 0

    def is_open(self):
        return self.__opened__

    def close(self):
        os.close(self.__fd__)
        self.__fd__ = 0
        self.__opened__ = False

    def wep(self, key='', key_id=0):
        # Match and parse WEP key
        tmp_key = ""

        if re.match('^([0-9a-fA-F]{2}){5}$', key) or re.match ('^([0-9a-fA-F]{2}){13}$', key):
            tmp_key = key
        elif re.match('^([0-9a-fA-F]{2}[:]){4}[0-9a-fA-F]{2}$', key) or re.match('^([0-9a-fA-F]{2}[:]){12}[0-9a-fA-F]{2}$', key):
            tmp_key = re.sub(':', '', key)
        elif re.match ('^([0-9a-fA-F]{4}[-]){2}[0-9a-fA-F]{2}$', key) or re.match ('^([0-9a-fA-F]{4}[-]){6}[0-9a-fA-F]{2}$', key):
            tmp_key = re.sub('-', '', key)
        else:
            return

        g = lambda x: chr(int(tmp_key[::2][x],16)*16+int(tmp_key[1::2][x],16))

        for i in range(len(tmp_key)/2):
            self.wepkey += g(i)

        if key_id > 3 or key_id < 0:
            self.key_id = 0
        else:
            self.key_id = key_id

        self.has_wep = True

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4 autoindent
