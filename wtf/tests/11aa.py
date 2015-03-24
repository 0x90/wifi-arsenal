# Copyright cozybit, Inc 2010-2011
# All rights reserved

"""
Test mesh 11aa performance (using ath9k_htc cards)

NOTE: specify test video file with ennvironment variable REF_CLIP

These tests comprise scripts for assessing the feasibility of multicast HD
video over wifi. Things you will need:

    - qpsnr in your path, see: git://github.com/hsanson/qpsnr.git
    - cvlc installed on your test nodes
    - custom 9271 fw with mcast rate patch

    vlc (can't run as root):
        server:
        cvlc -I dummy $file :sout="#rtp{dst=$client_ip,port=5004,mux=ts,ttl=1}" :sout-all :sout-keep vlc://quit

        client:
        cvlc -I dummy rtp://$client_ip --sout file/ts:out.ts

    hint: sync multiple mcast recepients with '--netsync-master' on the server
          and '--netsync-master-ip=<server_ip>' on the clients.

    qpsnr:
        ./qpsnr -a avg_ssim -s100 -m1000 -o fpa=1000 -r <ref_vid> <recv_vid>
        ./qpsnr -a avg_psnr -s100 -m1000 -o fpa=1000 -r <ref_vid> <recv_vid>

TODO: The idea is to run these in a controlled environment simulating
"real-world" conditions by generating contention and collisions. For now the
tests are just run in an enclosure.

Each test surverys the link quality with iperf and some video streaming
metrics, but modifies the channel type and unicast / mcast address.
Test script:
    0. run UDP iperf and get throughput / losses
    1. stream video and do quality metric analysis
    2. change mesh conf for next test

We test the following link cases:
    1. unicast HT20.
    2. unicast noHT.
    3. mcast MCS7.
    4. mcast 54mb/s

"""

import wtf.node.mesh as mesh
import unittest
import time
import wtf
from wtf.util import *
import sys
err = sys.stderr
import time
import os

wtfconfig = wtf.conf
sta = wtfconfig.mps

mcast_dst = "224.0.0.0"
ref_clip = os.getenv("REF_CLIP")
# XXX: nose probably has something like this?
results = {}

# global setup, called once during this suite


def setUp(self):

# if_1 <-> if_2
    global if_1
    global if_2

    for n in wtfconfig.mps:
        n.shutdown()
        n.init()
        n.start()


def tearDown(self):
    for n in wtfconfig.nodes:
        n.stop()

    print "                                                     ref_clip=%s" % (ref_clip,)
    print_linkreports(results)


class Test11aa(unittest.TestCase):

# run before / after each test
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_1_unicast_ht20(self):
        fname = sys._getframe().f_code.co_name

        dst_ip = if_2.ip

        perf_report = do_perf([if_1, if_2], dst_ip)
        vqm_report = do_vqm([if_1, if_2], dst_ip, ref_clip)
        vqm_report = do_vqm(sta[:2], dst_ip, ref_clip)

        results[fname] = LinkReport(
            perf_report=perf_report, vqm_report=vqm_report)

    def test_2_unicast_noht(self):
        fname = sys._getframe().f_code.co_name

        for mp in wtfconfig.mps:
            mp.iface[0].conf.htmode = ""
            mp.reconf()

        dst_ip = if_2.ip

        perf_report = do_perf([if_1, if_2], dst_ip)
        vqm_report = do_vqm(sta[:2], dst_ip, ref_clip)

        results[fname] = LinkReport(
            perf_report=perf_report, vqm_report=vqm_report)

    def test_3_mcast_mcs7(self):
        # XXX: need new firmware, derp
        # better to support mcast_rate in kernel and 9271 firmware
        pass

    def test_4_mcast_54mbps(self):
        # hard-coded to 54mbps for now
        fname = sys._getframe().f_code.co_name

        for mp in wtfconfig.mps:
            mp.iface[0].conf.mesh_params = "mesh_ttl=1"
            mp.iface[0].conf.mcast_rate = "54"
            mp.iface[0].mcast_route = mcast_dst
            mp.reconf()

        perf_report = do_perf([if_1, if_2], mcast_dst)
        vqm_report = do_vqm(sta[:2], mcast_dst, ref_clip)

        results[fname] = LinkReport(
            perf_report=perf_report, vqm_report=vqm_report)
