#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
#    This file is part of PyLorcon2.
#
#    PyLorcon2 is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    PyLorcon2 is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with PyLorcon2.  If not, see <http://www.gnu.org/licenses/>.

import sys
import unittest

import PyLorcon2

class PyLorcon2TestCase(unittest.TestCase):
    iface = 'wlan0'
    vap = iface
    driver = 'mac80211'
    # data is a beacon packet with bssid == 00:21:21:21:21:21
    data = "\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x21\x21" \
           "\x21\x21\x21\x00\x21\x21\x21\x21\x21\x90\x83\x50\x8c" \
           "\xf4\x38\x23\x00\x00\x00\x64\x00\x11\x04\x00\x04XXXX" \
           "\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x01" \
           "\x32\x04\x0c\x12\x18\x60"
    timeout = 123
    channel = 1
    mac =  (0, 2, 114, 105, 40, 255)

    def setUp(self):
        self.ctx = PyLorcon2.Context(self.iface)

    def tearDown(self):
        self.ctx.close()

    def testGetVersion(self):
        version = PyLorcon2.get_version()
        self.assertEqual(type(version), int)

    def testListDrivers(self):
        drivers = PyLorcon2.list_drivers()
        self.assertEqual(type(drivers), list)
        self.assertTrue(len(drivers) > 0)

    def testFindDriver(self):
        driver, description = PyLorcon2.find_driver(self.driver)
        self.assertEqual(self.driver, driver)
        self.assertEqual(type(description), str)

    def testAutoDriver(self):
        # Is it wise to test this? May fail depending on where it is tested
        # without a bug/error in Lorcon2 itself...
        driver, description = PyLorcon2.auto_driver(self.iface)
        self.assertEqual(self.driver, driver)
        self.assertEqual(type(description), str)
        
    def testInjection(self):
        self.ctx.open_injmon()
        num_sent = self.ctx.send_bytes(self.data)
        # The driver may or may not put a RadioTap-header in front of our
        # packet, so num_sent may be larger than len(self.data). The two are
        # equal if this is done in hardware.
        self.assertTrue(num_sent >= len(self.data))

    def testTimeout(self):
        self.ctx.set_timeout(self.timeout)
        timeout = self.ctx.get_timeout()
        self.assertEqual(self.timeout, timeout)

    def testVap(self):
        self.ctx.set_vap(self.vap)
        vap = self.ctx.get_vap()
        self.assertEqual(self.vap, vap)

    def testGetDriverName(self):
        drv = self.ctx.get_driver_name()
        self.assertEqual(type(drv), str)
    
    def testChannel(self):
        self.ctx.open_injmon()
        self.ctx.set_channel(self.channel)
        channel = self.ctx.get_channel()
        self.assertEqual(self.channel, channel)
    
    def testMAC(self):
        self.ctx.open_monitor()
        self.ctx.set_hwmac(self.mac)
        mac = self.ctx.get_hwmac()
        self.assertEqual(self.mac, mac)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        PyLorcon2TestCase.iface = sys.argv[1]

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(PyLorcon2TestCase)
    unittest.TextTestRunner(verbosity=2).run(suite)
