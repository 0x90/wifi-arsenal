#!/usr/bin/env python

from sulley import *
from sta_settings import *
from sta_requests import *
import socket
import time
import struct

# Assume that wireless card is in monitor mode on appropriate channel
# Saves from lot of dependencies (lorcon, pylorcon...)

def listen(s):
    """
    Returns whenever STA active scanning is detected.
    """
    global STA_MAC

    def isscan(pkt):
        if len(pkt) >= 24:
            if pkt[0] == "\x40" and pkt[10:16] == mac2str(STA_MAC):
                return True
        return False

    sess.log("waiting for active scanning from %s" % STA_MAC)
    while True:
        ans = s.recv(1024)
        answered = isscan(ans)
        if answered:
            sess.log("active scanning detected from %s" % STA_MAC)
            return True

def is_alive():

    global IFACE
    ETH_P_ALL = 3

    def isscan(pkt):
        if len(pkt) >= 24:
            if pkt[0] == "\x40" and pkt[10:16] == mac2str(STA_MAC):
                return True
        return False

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((IFACE, ETH_P_ALL))

    alive = False
    sess.log("waiting for active scanning from %s" % STA_MAC)
    start_time = time.time()

    while (time.time() - start_time < LISTEN_TIME):
        ans = s.recv(1024)
        if isscan(ans):
            alive = True
            break

    return alive

# Defining the transport protocol
sess    = sessions.session(session_filename=FNAME, proto="wifi", repeat_time=REPEAT_TIME, timeout=5.0, sleep_time=0, skip=SKIP)

# Defining the target
target  = sessions.target(STA_MAC, 0)

# Defining the instrumentation
target.procmon = instrumentation.external(post=is_alive)

# Adding the listen() function for target monitoring
sess.pre_send = listen

# Adding the IFACE for socket binding
sess.wifi_iface = IFACE

# Adding the target to the fuzzing session
sess.add_target(target)

# Adding tests
sess.connect(s_get("ProbeResp: Most Used IEs"))

for ie in list_ies:
    sess.connect(s_get("ProbeResp: IE %d" % ie))

sess.connect(s_get("ProbeResp: Malformed"))

for type_subtype in range(256):
    sess.connect(s_get("Fuzzy: Malformed %d" % type_subtype))

for oui in ouis:
    sess.connect(s_get("ProbeResp: Vendor Specific %s" % oui))

for method in ['WPA-PSK', 'RSN-PSK', 'WPA-EAP', 'RSN-EAP']:
    sess.connect(s_get("ProbeResp: %s Fuzzing" % method))

# Launching the fuzzing campaign
sess.fuzz()
