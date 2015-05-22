#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# fakeap.fakeap
#
# Copyright 2013 Konrad Markus
#
# Author: Konrad Markus <konker@gmail.com>
#

'''
Act as a fake Wi-Fi access point (AP) by periodically braodcasting
beacon packets.
Advertise that WPA2-PSK authentication is necessary,
although no successful authentication will be possible.
A callback is triggered whenever the access point detects 802.11
management frames of the following types:
    0 - probe request
    2 - association request
    4 - re-association request (?)
'''

import logging
import signal
from threading import Thread
import pyev
import time

from scapy.layers import dot11
from scapy.all import sniff, Dot11
import PyLorcon2


MANAGEMENT_FRAME_TYPE = 0x0
MANAGEMENT_FRAME_SUBTYPES = (0x0, 0x2, 0x4)


class PacketSender(object):
    def __init__(self, iface):
        self.iface = iface
        self.ctx = PyLorcon2.Context(self.iface)
        self.ctx.open_injmon()


    def send(self, packet):
        self.ctx.send_bytes(str(packet))


    def close(self):
        self.ctx.close()


class FakeAP(object):
    def __init__(self, iface, essid, bssid, channel, beacon_interval_sec, packet_callback):
        self.active = False
        self.iface = iface
        self.essid = essid
        self.bssid = bssid
        self.channel = channel
        self.beacon_interval_sec = beacon_interval_sec
        self.packet_callback = packet_callback

        self.start_time_secs = time.time()
        self.sc = 0
        self.sender = PacketSender(self.iface)

        self.beacon_packet = dot11.Dot11(addr1='ff:ff:ff:ff:ff:ff',       \
                                         addr2=self.bssid,                \
                                         addr3=self.bssid)                \
                             / dot11.Dot11Beacon(cap='ESS+privacy')       \
                             / dot11.Dot11Elt(ID='SSID',                  \
                                              info=self.essid)            \
                             / dot11.Dot11Elt(ID='DSset',                 \
                                              info=chr(self.channel))     \
                             / dot11.Dot11Elt(ID='Rates',                 \
                                              info='\x82\x84\x0b\x16')    \
                             / dot11.Dot11Elt(ID='RSNinfo',
                                              info='\x01\x00\x00\x0f\xac' \
                                                   '\x04\x01\x00\x00\x0f' \
                                                   '\xac\x04\x01\x00\x00' \
                                                   '\x0f\xac\x02\x00\x00')
        self.watchers = {
            "interval": None,
            "timeout": None
        }
        self.loop = pyev.Loop()

        # initialize and start a signal watchers
        sigterm_watcher = pyev.Signal(signal.SIGTERM, self.loop, self.sigterm_cb)
        sigterm_watcher.start()
        sigint_watcher = pyev.Signal(signal.SIGINT, self.loop, self.sigint_cb)
        sigint_watcher.start()

        self.loop.data = [sigterm_watcher, sigint_watcher]

        self.sniff_thread = Thread(target=self.sniff,
                                  kwargs=dict(),
                                  name='sniff-thread')
        self.sniff_thread.setDaemon(True)


    def sniff(self):
        # start sniffing for probe requests
        logging.info("Sniff starting...")
        sniff(iface=self.iface, prn=self.sniffCallback)


    def sniffCallback(self, p):
        if p.haslayer(Dot11):
            if p.type == MANAGEMENT_FRAME_TYPE and \
                            p.subtype in MANAGEMENT_FRAME_SUBTYPES:
                if True or p.addr1 == self.bssid:
                    self.packet_callback(p)


    def do_beacon(self):
        self.prepare_next_packet()
        self.send_packet()
        logging.debug("[%s] BEACON: %s" % (self.essid, self.beacon_packet.summary()))
    

    def prepare_next_packet(self):
        self.beacon_packet.SC = self.next_sequence_ctrl()

        # timestamp is the number of milliseconds the AP has been active
        self.beacon_packet[dot11.Dot11Beacon].timestamp = \
                        (time.time() - self.start_time_secs) * 1000


    def send_packet(self):
        self.sender.send(self.beacon_packet)


    # get next sequence number
    def next_sequence_ctrl(self):
        self.sc = (self.sc + 0x10) % 0xffff
        return self.sc


    # execute the command
    def interval_cb(self, watcher, revents):
        logging.debug("[%s] Interval complete: %s secs." % (self.essid, self.beacon_interval_sec))

        if self.active:
            logging.warning("[%s] Interval callback when still in active state. Skipping" % (self.essid))
            return

        self.active = True
        self.cancel_interval()

        # send out beacon packet
        self.do_beacon()

        # restart the interval
        self.active = False
        self.set_interval()


    def init_interval(self):
        if self.beacon_interval_sec > 0:
            self.watchers["interval"] = pyev.Timer(self.beacon_interval_sec, 0.0, self.loop, self.interval_cb)


    def set_interval(self):
        if self.beacon_interval_sec > 0:
            logging.debug("[%s] Adding interval timer: %s secs." % (self.essid, self.beacon_interval_sec))

            if not self.watchers["interval"]:
                self.init_interval()
            else:
                self.watchers["interval"].set(self.beacon_interval_sec, 0.0)

            self.watchers["interval"].start()


    def cancel_interval(self):
        if self.watchers["interval"] and self.watchers["interval"].active:
            logging.debug("[%s] Cancel interval" % (self.essid))
            self.watchers["interval"].stop()


    def sigterm_cb(self, watcher, revents):
        logging.info("SIGTERM caught. Exiting..")
        self.halt()


    def sigint_cb(self, watcher, revents):
        logging.info("SIGINT caught. Exiting..")
        self.halt()


    def start(self):
        logging.info("Event loop start")
        self.sniff_thread.start()
        logging.info("Sniffer started")
        self.set_interval()
        self.loop.start()


    def halt(self):
        logging.info("Halting...")
        self.loop.stop(pyev.EVBREAK_ALL)
        self.sender.close()



