#!/usr/bin/env python

from sulley import *
from ap_requests import *
from optparse import OptionParser

import re
import socket
import struct
import time

# Assume that wireless card is in monitor mode on appropriate channel
# Saves from lot of dependencies (lorcon, pylorcon...)

###############

def fuzz_ap():

    def is_alive():

        global IFACE, AUTH_REQ_OPEN
        ETH_P_ALL = 3

        def isresp(pkt):
            resp = False
            if (len(pkt) >= 30 and pkt[0] == "\xB0"\
                and pkt[4:10] == mac2str(STA_MAC)\
                and pkt[28:30] == "\x00\x00"):
                resp = True
            return resp

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((IFACE, ETH_P_ALL))

        sess.log("checking aliveness of fuzzed access point %s" % AP_MAC, level=3)

        retries = CRASH_RETRIES
        alive = False

        while retries:

            s.send(AUTH_REQ_OPEN)

            start_time = time.time()
            while (time.time() - start_time) < 1:
                ans = s.recv(1024)
                alive = isresp(ans)
                if alive:
                    s.send(DEAUTH)
                    s.close()
                    if retries != CRASH_RETRIES:
                        sess.log("retried authentication %d times" % (CRASH_RETRIES - retries), level=1)
                    return alive

            retries -= 1

        s.close()

        return alive

    def check_alive(s):

        global AUTH_REQ_OPEN

        def isresp(pkt):
            resp = False
            if (len(pkt) >= 30 and pkt[0] == "\xB0"\
                and pkt[4:10] == mac2str(STA_MAC)\
                and pkt[28:30] == "\x00\x00"):
                resp = True
            return resp

        sess.log("checking aliveness of fuzzed access point %s" % AP_MAC, level=3)

        while True:
            t = s.send(AUTH_REQ_OPEN)
            start_time = time.time()
            while (time.time() - start_time) < 1:
                alive = isresp(s.recv(1024))
                if alive:
                    return alive
            sess.log("waiting for the access point to be up", level=1)
            time.sleep(DELAY_REBOOT)

    def pass_state(s):
        '''
        '''
        return True

    def clean_state(s):

        global DEAUTH

        s.send(DEAUTH)
        sess.log("sending deauthentication to come back to initial state", level=3)

    # shameless ripped from scapy
    def hexdump(x):
        x=str(x)
        l = len(x)
        i = 0
        while i < l:
            print "%04x  " % i,
            for j in range(16):
                if i+j < l:
                    print "%02X" % ord(x[i+j]),
                else:
                    print "  ",
                if j%16 == 7:
                    print "",
            print " ",
            print x[i:i+16]
            i += 16

    def check_auth(session, node, edge, sock):

        def isresp(pkt):
            resp = False
            if (len(pkt) >= 30 and pkt[0] == "\xB0"\
                and pkt[4:10] == mac2str(STA_MAC)\
                and pkt[28:30] == "\x00\x00"):
                resp = True
            return resp

        start_time = time.time()
        while (time.time() - start_time) < STATE_WAIT_TIME:
            pkt = sock.recv(1024)
            ans = isresp(pkt)
            if ans:
                sess.log("authentication successfull with %s" % AP_MAC, level=3)
                return

        sess.log("authentication not successfull with %s" % AP_MAC, level=1)

        if session.fuzz_node.mutant != None:
            '''
            print "XXXXX : session.fuzz_node.name %s" % session.fuzz_node.name
            print "XXXXX : session.fuzz_node.mutant_index %d" % session.fuzz_node.mutant_index
            print "XXXXX : session.fuzz_node.mutant.mutant_index %d" % session.fuzz_node.mutant.mutant_index
            print "XXXXX : session.fuzz_node.num_mutations() %d" % session.fuzz_node.num_mutations()
            print "XXXXX : session.total_mutant_index %d" % session.total_mutant_index
            '''
            sess.log("re-trying the current test case", level=1)
            session.fuzz_node.mutant_index -= 1
            session.fuzz_node.mutant.mutant_index -= 1
            session.total_mutant_index -= 1

    def check_asso(session, node, edge, sock):

        def isresp(pkt):
            resp = False
            if (len(pkt) >= 30 and pkt[0] == "\x10"\
                and pkt[4:10] == mac2str(STA_MAC)\
                and pkt[26:28] == "\x00\x00"):
                resp = True
            return resp

        start_time = time.time()
        while (time.time() - start_time) < STATE_WAIT_TIME:
            pkt = sock.recv(1024)
            ans = isresp(pkt)
            if ans:
                sess.log("association successfull with %s" % AP_MAC, level=3)
                return

        sess.log("association not successfull with %s" % AP_MAC, level=1)
        if session.fuzz_node.mutant != None:
            '''
            print "XXXXX : session.fuzz_node.name %s" % session.fuzz_node.name
            print "XXXXX : session.fuzz_node.mutant_index %d" % session.fuzz_node.mutant_index
            print "XXXXX : session.fuzz_node.mutant.mutant_index %d" % session.fuzz_node.mutant.mutant_index
            print "XXXXX : session.fuzz_node.num_mutations() %d" % session.fuzz_node.num_mutations()
            print "XXXXX : session.total_mutant_index %d" % session.total_mutant_index
            '''
            sess.log("re-trying the current test case", level=1)
            session.fuzz_node.mutant_index -= 1
            session.fuzz_node.mutant.mutant_index -= 1
            session.total_mutant_index -= 1



    # Defining the transport protocol
    sess    = sessions.session(session_filename=FNAME, proto="wifi", timeout=5.0, sleep_time=0.1, log_level=LOG_LEVEL, skip=SKIP, crash_threshold=CRASH_THRESHOLD)

    # Defining the target
    target  = sessions.target(AP_MAC, 0)

    # Adding the detect_crash function for target monitoring
    target.procmon = instrumentation.external(post=is_alive)

    # Adding a check for alive of access point
    sess.pre_send = check_alive

    # Adding a deauth send to come back to initial state
    sess.post_send = clean_state

    # Adding the IFACE for socket binding
    sess.wifi_iface = IFACE

    # Adding the target to the fuzzing session
    sess.add_target(target)

    # Fuzzing State "Not Authenticated, Not Associated"

    sess.connect(s_get("AuthReq: Open"))

    for type_subtype in range(256): # 256
        sess.connect(s_get("Fuzzy 1: Malformed %d" % type_subtype))

    # Fuzzing State "Authenticated, Not Associated"
    sess.connect(s_get("AuthReq: Open"), s_get("AssoReq: Garbage"), callback=check_auth)    # Checking Authentication
    sess.connect(s_get("AuthReq: Open"), s_get("AssoReq: Open"), callback=check_auth)       # Checking Authentication
    sess.connect(s_get("AuthReq: Open"), s_get("AssoReq: %s" % AP_CONFIG), callback=check_auth)    # Checking Authentication
    if AP_CONFIG not in ['Open']:
        sess.connect(s_get("AuthReq: Open"), s_get("AssoReq: %s Fuzzing" % AP_CONFIG ), callback=check_auth)    # Checking Authentication

    for oui in ouis:
        sess.connect(s_get("AuthReq: Open"), s_get("AssoReq: Vendor Specific %s" % oui), callback=check_auth)

    for ie in list_ies:
        sess.connect(s_get("AuthReq: Open"), s_get("AssoReq: IE %d" % ie), callback=check_auth)

    #for type_subtype in range(256):
        sess.connect(s_get("AuthReq: Open"), s_get("Fuzzy 2: Malformed %d" % type_subtype), callback=check_auth)

    # Fuzzing State : "Authenticated, Associated"

    for type_subtype in range(256):
        sess.connect(s_get("AssoReq: %s" % AP_CONFIG), s_get("Fuzzy 3: Malformed %d" % type_subtype), callback=check_asso)

    if AP_CONFIG in ['WPA-PSK', 'RSN-PSK']:
        sess.connect(s_get("AssoReq: %s" % AP_CONFIG), s_get("EAPoL-Key: %s" % AP_CONFIG), callback=check_asso)

    if AP_CONFIG in ['WPA-EAP', 'RSN-EAP']:
        sess.connect(s_get("AssoReq: %s" % AP_CONFIG), s_get("EAPoL-Start: %s" % AP_CONFIG), callback=check_asso)

    # Launching the fuzzing campaign
    sess.fuzz()
   
if __name__ == '__main__':

    usage = 'usage: %prog [options]'
    parser = OptionParser(usage)
    parser.add_option('--sta_mac', dest='sta_mac', help='STA MAC address (fuzzer)')
    parser.add_option('--iface', dest='iface', help='injection interface')
    parser.add_option('--skip', dest='skip', help='skip tests (int)', type='int', default=0)
    parser.add_option('--ssid', dest='ssid', help='AP ssid (fuzzed)')
    parser.add_option('--ap_mac', dest='ap_mac', help='AP MAC address (fuzzed)')
    parser.add_option('--channel', dest='channel', help='AP channel (fuzzed)', type=int)
    parser.add_option('--ap_config', dest='ap_config', help='AP config: Open, WPA-PSK, WPA-EAP, RSN-PSK, RSN-EAP')
    parser.add_option('--save', dest='save', help='save results', action='store_true', default=False)
    parser.add_option('--truncate', dest='truncate', help='truncate frames option', action='store_true', default=False)
    parser.add_option('--crash_retries', dest='crash_retries', type=int, default=10)
    parser.add_option('--delay', dest='delay', type=int, default=1)
    parser.add_option('--delay_reboot', dest='delay_reboot', type=int, default=10)
    parser.add_option('--state_wait_time', dest='state_wait_time', type=int, default=2)
    parser.add_option('--log_level', dest='log_level', type=int, default=3)
    parser.add_option('--crash_threshold', dest='crash_threshold', type=int, default=3)
    parser.add_option('--fname', dest='fname', help='defining saved results file (conjointly with --save)', default=None)

    (options, args) = parser.parse_args()

    if not options.sta_mac:
        parser.error('STA MAC address must be set')
    if not re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', options.sta_mac, re.I).group():
        parser.error('STA MAC address invalid format')
    if not options.iface:
        parser.error('injection interface must be set')
    if not options.ssid:
        parser.error('AP ssid must be set')
    if len(options.ssid) > 32:
        parser.error('AP ssid must be <= 32 characters')
    if not options.ap_mac:
        parser.error('AP MAC address must be set')
    if not re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', options.ap_mac, re.I).group():
        parser.error('AP MAC address invalid format')
    if not options.channel:
        parser.error('AP channel must be set')
    if not options.ap_config:
        parser.error('AP config must be set')
    if options.ap_config not in [ 'Open', 'WPA-PSK', 'WPA-EAP', 'RSN-PSK', 'RSN-EAP' ]:
        parser.error('AP incorrect configuration')
    if options.save:
        if options.fname:
            FNAME = fname
        else:
            FNAME = 'audits/ap-%s-%s.session' % (options.ap_mac, options.ap_config)
    
    STA_MAC = options.sta_mac
    IFACE = options.iface
    SAVE_RESULTS = options.save
    SKIP = options.skip
    SSID = options.ssid
    AP_MAC = options.ap_mac
    CHANNEL = options.channel
    AP_CONFIG = options.ap_config
    CRASH_RETRIES = options.crash_retries  
    DELAY = options.delay
    STATE_WAIT_TIME = options.state_wait_time
    DELAY_REBOOT = options.delay_reboot
    LOG_LEVEL = options.log_level
    CRASH_THRESHOLD = options.crash_threshold
    TRUNCATE = options.truncate
    
    fuzz_ap()
