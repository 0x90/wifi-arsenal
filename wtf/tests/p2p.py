# Copyright cozybit, Inc 2010-2011
# All rights reserved

import wtf
import time
import unittest
wtfconfig = wtf.conf


def setUp(self):
    for n in wtfconfig.nodes:
        n.shutdown()
        n.init()


class TestP2P(unittest.TestCase):

    def setUp(self):
        for n in wtfconfig.nodes:
            n.stop()

    # Helper routines
    def expect_find(self, n0, n1):
        # expect that n1 shows up in n0's list of peers
        count = 10
        while count != 0:
            peers = n0.peers()
            for p in peers:
                if p.mac == n1.mac and \
                        p.name == n1.name:
                    return
            count = count - 1
            time.sleep(1)
        self.failIf(1, "%s failed to find %s" % (n0.name, n1.name))

    # Actual tests start here
    def test_find_peer(self):
        wtfconfig.p2ps[0].start()
        wtfconfig.p2ps[1].start()
        wtfconfig.p2ps[0].find_start()
        wtfconfig.p2ps[1].find_start()
        self.expect_find(wtfconfig.p2ps[0], wtfconfig.p2ps[1])
        self.expect_find(wtfconfig.p2ps[1], wtfconfig.p2ps[0])

    def test_simple_pbc_connect(self):
        go = wtfconfig.p2ps[0]
        client = wtfconfig.p2ps[1]
        go.start(auto_go=True)
        client.start(client_only=True)
        client.find_start()
        # does client see GO?
        self.expect_find(client, go)
        client.find_stop()
        # can client connect to GO?
        ret = client.connect_start(go)
        self.failIf(ret != 0, "%s failed to initiate connection from %s" %
                    (client.name, go.name))
        ret = go.pbc_push()
        self.failIf(ret != 0, "Failed to push button on GO %s" % go.name)
        ret = client.connect_finish(go)
        self.failIf(ret != 0, "Failed to connect to %s" % go.name)
        go.set_ip("192.168.88.1")
        client.set_ip("192.168.88.2")
        self.failIf(client.ping("192.168.88.1", timeout=5).return_code != 0,
                    "client failed to ping GO")
        # Finally, perform a traffic test
        go.perf()
        client.perf("192.168.88.1")
        go.killperf()

    def test_go_initiates_pbc(self):
        go = wtfconfig.p2ps[0]
        go.intent = 15
        client = wtfconfig.p2ps[1]
        go.start()
        client.start()
        client.find_start()
        go.find_start()
        # do they find eachother?
        self.expect_find(client, go)
        self.expect_find(go, client)

        # can GO connect to client?
        ret = client.connect_allow(go)
        self.failIf(ret != 0, "%s failed to allow connection to %s" %
                    (client.name, go.name))
        ret = go.connect_start(client)
        self.failIf(ret != 0, "%s failed to initiate connection to %s" %
                    (go.name, client.name))
        ret = go.connect_finish(client)
        self.failIf(ret != 0, "Failed to connect to %s" % client.name)
        ret = client.connect_finish(client)
        self.failIf(ret != 0, "Failed to connect to %s" % go.name)
        go.set_ip("192.168.88.1")
        client.set_ip("192.168.88.2")
        self.failIf(client.ping("192.168.88.1", timeout=5).return_code != 0,
                    "client failed to ping GO")
