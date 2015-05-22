#!/usr/bin/env python
import logging
from nose.tools import assert_equal, assert_not_equal
from wpp.location import getWLAN, fixPosWLAN
from wpp.db import WppDB
from wpp.config import dbsvrs, DB_ONLINE, wpplog, Formatter, loghandler
logfmt = Formatter('<%(asctime)s,%(levelname)s ==> %(message)s')
loghandler.setFormatter(logfmt)
wpplog.addHandler(loghandler)
wpplog.setLevel(logging.DEBUG)

def test_fixPosWLAN():
    """WLAN positioning test case 1-31"""
    # $ for i in $(seq 31); do python wpp/location.py -f $i; done
    # $ egrep -A1 'final|NO cluster' wpp.log |grep -v 'Sele' |grep -v final |grep -v  '\-\-' | \
    # sed  's/^<2011.*$/\[\]/g' |sed 's/\(.*\)/\1,/g'
    poss_ok = [ [], [], [], [], [], [], [],
                [39.912616, 116.3521475, 50],
                [39.912782, 116.352266, 50],
                [39.91257075, 116.35363975, 122.54288388709156],
                [39.912613571428572, 116.35301342857143, 108.37042404018443],
                [39.91257075, 116.35363975, 122.54288388709156],
                [39.91245, 116.352029, 50],
                [39.91257199999999, 116.35131033333333, 96.876048832124482],
                [39.910843, 116.352233, 50],
                [39.912782, 116.352266, 50],
                [39.912506666666665, 116.34972933333334, 50],
                [39.896571000000002, 116.347176, 100],
                [], [],
                [39.894749695652173, 116.34846693478261, 504.49033670393203],
                [39.903174187499999, 116.3043408125, 205.26326958257582],
                [39.911346999999999, 116.367709, 50],
                [39.905437777777777, 116.30197872222223, 71.863904363421156],
                [39.898307000000003, 116.367233, 50],
                [39.896256999999999, 116.345404, 50],
                [39.866599000000001, 116.33084275, 140.93180577820135],
                [39.898285222222221, 116.37795088888889, 50],
                [39.907567142857147, 116.3518077142857, 82.052322921173257],
                [39.906203714285709, 116.31805528571428, 50],
                [39.907556527131781, 116.35137625581396, 50],]
    dbsvr = dbsvrs[DB_ONLINE] 
    wppdb = WppDB(dsn=dbsvr['dsn'], dbtype=dbsvr['dbtype'])
    for i, pos_ok in enumerate(poss_ok):
        len_visAPs, wifis = getWLAN(i+1)
        pos_test = fixPosWLAN(len_visAPs, wifis, wppdb, True)
        assert_equal(pos_ok, pos_test)
