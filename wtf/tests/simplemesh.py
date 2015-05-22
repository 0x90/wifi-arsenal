# Copyright cozybit, Inc 2010-2011
# All rights reserved

"""
Simple test of throughput from one mesh node to another.
"""

import wtf.node.mesh as mesh
from wtf.util import *
import unittest
import wtf
import sys
import os

err = sys.stderr
wtfconfig = wtf.conf
sta = wtfconfig.mps

ref_clip = os.getenv("REF_CLIP")
# XXX: nose probably has something like this?
path_heal_time = {}
results = {}

# set default test results and override if provided
exp_results = {"test1": 0.01, "test2": 0.01}
if len(wtfconfig.exp_results) > 0:
    exp_results = wtfconfig.exp_results


# global setup, called once during this suite
def setUp(self):
    """Make global interface variable out of all sta iface[0]."""
    global g_ifs

    g_ifs = [STA.iface[0] for STA in sta]


def tearDown(self):
    for n in wtfconfig.nodes:
        n.stop()

    print "                                                     \
            ref_clip=%s" % (ref_clip,)
    if len(results) > 0:
        print_linkreports(results)
    if len(path_heal_time) > 0:
        print "Path healed in:        " + str(path_heal_time["path_heal"]) + " seconds"


def init_nodes(n=3):
    """Start up only number of nodes desired."""
    for i in range(n):
        wtfconfig.mps[i].init()
        wtfconfig.mps[i].start()


class SimpleMeshTest(unittest.TestCase):

# run before / after each test
    def setUp(self):
        """Shutdown all nodes before each test."""
        for n in wtfconfig.mps:
            n.shutdown()

    def tearDown(self):
        pass

    def test_1_throughput(self):
        fname = sys._getframe().f_code.co_name
        # two node test
        init_nodes(2)

        dst_ip = g_ifs[1].ip

        perf_report = do_perf([g_ifs[0], g_ifs[1]], dst_ip)
        get_topology(g_ifs[:2], fname)
        results[fname] = LinkReport(perf_report=perf_report)
        logMeasurement('tput', perf_report.tput)
        logMeasurement('loss', perf_report.loss)
        self.failIf(perf_report.tput < (exp_results["test1"]),
                    "reported throughput (" + str(perf_report.tput) + ") is \
                    lower than expected (" + str(exp_results["test1"]) + ")")

    def test_2_same_ch_mhop(self):
        fname = sys._getframe().f_code.co_name

        # do a -> b -> c
        ifs = g_ifs[:3]
        old_params = []
        for iface in ifs:
            if iface != g_ifs[1]:
                old_params.append(iface.conf.mesh_params)
                iface.conf.mesh_params = "mesh_auto_open_plinks=0"
            iface.node.reconf()

        g_ifs[0].add_mesh_peer(g_ifs[1])
        g_ifs[2].add_mesh_peer(g_ifs[1])

        perf_report = do_perf([g_ifs[0], g_ifs[2]], g_ifs[2].ip)
        get_topology(g_ifs[:3], fname)

        # reset mesh params
        n = 0
        for iface in ifs:
            if iface != g_ifs[1]:
                iface.conf.mesh_params = old_params[n]
                n += 1

        # test multi-hop performance using a single radio for forwarding
        results[fname] = LinkReport(perf_report=perf_report)
        g_ifs[1].dump_mesh_stats()
        logMeasurement('tput', perf_report.tput)
        logMeasurement('loss', perf_report.loss)
        self.failIf(perf_report.tput < (exp_results["test2"]),
                    "reported throughput (" + str(perf_report.tput) + ") is \
                    lower than expected (" + str(exp_results["test2"]) + ")")

    def test_3_path_healing(self):
        """Kill a radio, then bring back and measure path heal time."""
        # two node test
        init_nodes(2)

        count = 30
        interval = .1
        found = 0

        # check if ping is alive
        ping_results = g_ifs[0].node.ping(g_ifs[1].ip, count=3).stdout
        ping_results = ping_results[-2]
        self.failIf(ping_results.find("100%") != -1,
                    "not connected on initial ping")

        # turn off radio and ping to make sure we drop all packets
        g_ifs[1].set_radio(0)
        ping_results = g_ifs[0].node.ping(
            g_ifs[1].ip, count=20, interval=.1, timeout=20).stdout
        ping_results = ping_results[-2]
        self.failIf(ping_results.find("100%") == -1,
                    "still connected")
        g_ifs[0].dump_mpaths()

        # turn back on radio and start ping
        g_ifs[1].set_radio(1)
        ping_results = g_ifs[0].node.ping(
            g_ifs[1].ip, count=count, interval=interval).stdout
        # look for first icmp_seq= and grab the request number
        for icmp in ping_results[1:]:
            if icmp.find("icmp_seq="):
                found = int(icmp.split(" ")[4][9:])
                break
        self.failIf(found == 0,
                    "Never reconnected after %d seconds" % (count * interval))

        # expects no loss after reconnected
        path_heal_time["path_heal"] = found * interval
        logMeasurement("found", path_heal_time["path_heal"])
        get_topology(g_ifs[:2], fname)
