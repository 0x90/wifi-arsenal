# Copyright cozybit, Inc 2010-2011
# All rights reserved

"""
Test infrastructure sta/ap connectivity
"""

import wtf.node.ap as AP
import unittest
import time
import wtf
wtfconfig = wtf.conf

AP_IP = "192.168.99.1"
STA_IP = "192.168.99.2"


def setUp(self):
    # start with all of the nodes initialized by idle
    for n in wtfconfig.nodes:
        n.shutdown()
        n.init()


def tearDown(self):
    for n in wtfconfig.nodes:
        n.stop()


class TestAPSTA(unittest.TestCase):

    def setUp(self):
        # start with all of the nodes stopped
        for n in wtfconfig.nodes:
            n.stop()
        # set IP addrs, stack doesn't care if iface goes up or down
        wtfconfig.aps[0].set_ip(AP_IP)
        wtfconfig.stas[0].set_ip(STA_IP)

    def startNodes(self):
        for n in wtfconfig.nodes:
            n.start()

    def pingTest(self):
        self.failIf(wtfconfig.stas[0].ping(AP_IP, timeout=5).return_code != 0,
                    "Failed to ping AP at %s" % AP_IP)

    def assocTest(self):
        self.failIf(wtfconfig.stas[0].assoc(wtfconfig.aps[0].config),
                    "Failed to associate with AP")

    def throughput(self):
        wtfconfig.aps[0].perf_serve()
        results = wtfconfig.stas[0].perf_client(AP_IP)
        wtfconfig.aps[0].killperf()

    def stressTest(self):
        wtfconfig.aps[0].perf_serve()
        results = wtfconfig.stas[0].stress(AP_IP)
        wtfconfig.aps[0].killperf()
        self.pingTest()

    def test_scan(self):
        wtfconfig.aps[0].config = AP.APConfig(ssid="wtf-scantest", channel=11)
        wtfconfig.aps[0].start()
        wtfconfig.stas[0].start()
        # try a few times since not all BSSs are found each scan
        found = None
        for i in range(3):
            results = wtfconfig.stas[0].scan()
            for r in results:
                if r.ssid == "wtf-scantest":
                    found = r
                    break
            if found != None:
                break

        self.failIf(found == None, "Failed to find ssid wtf-scantest")
        self.failIf(r.channel != 11, "Expected wtf-scantest on channel 11")

    def test_open_associate(self):
        wtfconfig.aps[0].config = AP.APConfig(ssid="wtf-assoctest", channel=6)

        self.startNodes()
        # give slow AP plenty of time to start
        time.sleep(5)
        self.assocTest()
        self.pingTest()
        self.throughput()

    def test_wpa_psk_tkip_assoc(self):
        wtfconfig.aps[0].config = AP.APConfig(ssid="wtf-wpatest",
                                              security=AP.SECURITY_WPA,
                                              auth=AP.AUTH_PSK,
                                              password="thisisasecret",
                                              encrypt=AP.ENCRYPT_TKIP)
        self.startNodes()
        self.assocTest()
        self.pingTest()

    def test_wpa2_psk_tkip_assoc(self):
        wtfconfig.aps[0].config = AP.APConfig(ssid="wtf-wpatest",
                                              security=AP.SECURITY_WPA2,
                                              auth=AP.AUTH_PSK,
                                              password="thisisasecret",
                                              encrypt=AP.ENCRYPT_TKIP)
        self.startNodes()
        self.assocTest()
        self.pingTest()

    def test_wpa_psk_ccmp_assoc(self):
        wtfconfig.aps[0].config = AP.APConfig(ssid="wtf-wpatest",
                                              security=AP.SECURITY_WPA,
                                              auth=AP.AUTH_PSK,
                                              password="thisisasecret",
                                              encrypt=AP.ENCRYPT_CCMP)
        self.startNodes()
        self.assocTest()
        self.pingTest()

    def test_wpa2_psk_ccmp_assoc(self):
        wtfconfig.aps[0].config = AP.APConfig(ssid="wtf-wpatest",
                                              security=AP.SECURITY_WPA2,
                                              auth=AP.AUTH_PSK,
                                              password="thisisasecret",
                                              encrypt=AP.ENCRYPT_CCMP)
        self.startNodes()
        self.assocTest()
        self.pingTest()
