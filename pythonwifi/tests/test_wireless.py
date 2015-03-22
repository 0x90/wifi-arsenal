#!/usr/bin/env python
# Copyright 2004-2008 Roman Joost <roman@bromeco.de> - Rotterdam, Netherlands
# this file is part of the python-wifi package - a python wifi library
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
import errno
import unittest
import types
from pythonwifi.iwlibs import Wireless, getNICnames
from pythonwifi.flags import modes, IW_ENCODE_RESTRICTED

class TestWireless(unittest.TestCase):

    def setUp(self):
        ifnames = getNICnames()
        self.wifi = Wireless(ifnames[0])

    def test_wirelessMethods(self):
        # test all wireless methods that they don't return an error
        methods = ['getAPaddr',
                   'getBitrate',
                   'getBitrates',
                   'getChannelInfo',
                   'getEssid',
                   'getFragmentation',
                   'getFrequency',
                   'getMode',
                   'getNwids',
                   'getWirelessName',
                   'getPowermanagement',
                   'getQualityMax',
                   'getQualityAvg',
                   'getRetrylimit',
                   'getRTS',
                   'getSensitivity',
                   'getTXPower',
                   'getStatistics',
                   'commit']

        for m in methods:
            result = getattr(self.wifi, m)()

        old_mode = self.wifi.getMode()
        self.wifi.setMode('Monitor')
        self.assert_(self.wifi.getMode() == 'Monitor')
        self.wifi.setMode(old_mode)

        old_essid = self.wifi.getEssid()
        self.wifi.setEssid('Joost')
        self.assert_(self.wifi.getEssid() == 'Joost')
        self.wifi.setEssid(old_essid)

        old_freq = self.wifi.getFrequency()
        self.wifi.setFrequency('2.462GHz')
        self.assert_(self.wifi.getFrequency() == '2.462GHz')
        self.wifi.setFrequency(old_freq)

        # test setAPaddr - does not work unless AP is real and available
        #old_mac = self.wifi.getAPaddr()
        #self.wifi.setAPaddr('61:62:63:64:65:66')
        #time.sleep(3)                                     # 3 second delay between set and get required
        #self.assert_(self.wifi.getAPaddr() == '61:62:63:64:65:66')
        #self.wifi.setAPaddr(old_mac)

        old_enc = self.wifi.getEncryption()
        self.wifi.setEncryption('restricted')
        self.assert_(self.wifi.getEncryption() == 'restricted')
        self.assert_(self.wifi.getEncryption(symbolic=False) \
                        == IW_ENCODE_RESTRICTED+1)
        self.wifi.setEncryption(old_enc)

        try:
            old_key = self.wifi.getKey()
        except ValueError, msg:
            old_key = None
        self.wifi.setKey('ABCDEF1234', 1)
        self.assert_(self.wifi.getKey() == 'ABCD-EF12-34')
        self.assert_(map(hex, self.wifi.getKey(formatted=False)) \
                        == ['0xab', '0xcd', '0xef', '0x12', '0x34'])
        if old_key:
            self.wifi.setKey(old_key, 1)
        else:
            self.wifi.setEncryption('off')


    def test_wirelessWithNonWifiCard(self):
        self.wifi.ifname = 'eth0'
        methods = ['getAPaddr',
                   'getBitrate',
                   'getBitrates',
                   'getChannelInfo',
                   'getEssid',
                   'getFragmentation',
                   'getFrequency',
                   'getMode',
                   'getNwids',
                   'getWirelessName',
                   'getPowermanagement',
                   'getQualityMax',
                   'getQualityAvg',
                   'getRetrylimit',
                   'getRTS',
                   'getSensitivity',
                   'getTXPower',
                   'commit']
    
        for m in methods:
            try:
                result = getattr(self.wifi, m)()
            except IOError, (error, msg):
                self.assertEquals(error, errno.EINVAL)

        try:
            result = self.wifi.getStatistics()
        except IOError, (error, msg):
            self.assertEquals(error, errno.EOPNOTSUPP)

        try:
            result = self.wifi.setMode('Monitor')
        except IOError, (error, msg):
            self.assertEquals(error, errno.EINVAL)

        try:
            result = self.wifi.setEssid('Joost')
        except IOError, (error, msg):
            self.assertEquals(error, errno.EINVAL)

        try:
            result = self.wifi.setFrequency('2.462GHz')
        except IOError, (error, msg):
            self.assertEquals(error, errno.EINVAL)

        try:
            result = self.wifi.setEncryption('restricted')
        except IOError, (error, msg):
            self.assertEquals(error, errno.EINVAL)

        try:
            result = self.wifi.setKey('ABCDEF1234', 1)
        except IOError, (error, msg):
            self.assertEquals(error, errno.EINVAL)


    def test_wirelessWithNonExistantCard(self):
        self.wifi.ifname = 'eth5'
        methods = ['getAPaddr',
                   'getBitrate',
                   'getBitrates',
                   'getChannelInfo',
                   'getEssid',
                   'getFragmentation',
                   'getFrequency',
                   'getMode',
                   'getNwids',
                   'getWirelessName',
                   'getPowermanagement',
                   'getQualityMax',
                   'getQualityAvg',
                   'getRetrylimit',
                   'getRTS',
                   'getSensitivity',
                   'getTXPower',
                   'commit']
    
        for m in methods:
            try:
                result = getattr(self.wifi, m)()
            except IOError, (error, msg):
                self.assertEquals(error, errno.ENODEV)

        try:
            result = self.wifi.setMode('Monitor')
        except IOError, (error, msg):
            self.assertEquals(error, errno.ENODEV)

        try:
            result = self.wifi.setEssid('Joost')
        except IOError, (error, msg):
            self.assertEquals(error, errno.ENODEV)

        try:
            result = self.wifi.setFrequency('2.462GHz')
        except IOError, (error, msg):
            self.assertEquals(error, errno.ENODEV)

        try:
            result = self.wifi.setEncryption('restricted')
        except IOError, (error, msg):
            self.assertEquals(error, errno.ENODEV)

        try:
            result = self.wifi.setKey('ABCDEF1234', 1)
        except IOError, (error, msg):
            self.assertEquals(error, errno.ENODEV)


suite = unittest.TestSuite()
suite.addTest(unittest.makeSuite(TestWireless))
unittest.TextTestRunner(verbosity=2).run(suite)
