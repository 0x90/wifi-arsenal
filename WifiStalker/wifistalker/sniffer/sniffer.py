# Author: Tomasz bla Fortuna
# License: GPLv2

import os
import sys
from time import time
from IPython import embed

from scapy import config, sendrecv

from wifistalker import Log, WatchDog

from hopper import Hopper
from parser import PacketParser


class Sniffer(object):
    "Channel hopping, packet sniffing, parsing and finally storing"

    def __init__(self, db, interface, related_interface, sniffer_name, enable_hopping,
                 use_24=True, use_pop5=False):
        self.db = db
        self.sniffer_name = sniffer_name
        self.interface = interface
        self.enable_hopping = enable_hopping

        # Check interface existance
        if not self._iface_exists(interface):
            print "Exiting: Interface %s doesn't exist" % interface
            sys.exit(1)

        if related_interface and not self._iface_exists(related_interface):
            print "Exiting: Related interface %s doesn't exist" % interface
            sys.exit(1)

        # Logging
        header = 'SNIFF'
        if sniffer_name:
            header += '_' + sniffer_name
        self.log = Log(self.db, use_stdout=True, header=header)

        # Submodules
        self.packet_parser = PacketParser(self.log)
        self.hopper = Hopper(self.log, interface, related_interface)
        ret = self.hopper.configure(use_24=use_24, use_pop5=use_pop5)
        if ret is False:
            sys.exit(1)

        config.conf.sniff_promisc = 0
        self.log.info("Promiscuous mode disabled")

        self.watchdog = WatchDog(interval=20)


    def _iface_exists(self, iface_name):
        "Check if interface exists"
        path = '/sys/class/net'
        iface_path = os.path.join(path, iface_name)
        try:
            _ = os.stat(iface_path)
            return True
        except OSError:
            return False

    def run(self):
        "Sniffer main loop"

        begin = time()
        pkts_all = 0

        sniff_begin = time()
        stat_prev = sniff_begin
        stat_every = 3 # seconds
        while True:
            start = time()

            # This catches KeyboardInterrupt,
            # TODO: Disable this catching + Probably hop on another thread and use prn argument.
            # But then - you'd have watchdog problems.
            pkts = sendrecv.sniff(iface=self.interface, count=20, timeout=0.1)
            pkts_all += len(pkts)
            for pkt in pkts:
                data = self.packet_parser.parse(pkt)
                if data is None:
                    continue

                data['ch'] = self.hopper.channel_number
                data['sniffer'] = self.sniffer_name

                if ('PROBE_REQ' in data['tags'] or
                    'PROBE_RESP' in data['tags'] or
                    'ASSOC_REQ' in data['tags'] or
                    'DISASS' in data['tags']):
                    # Increase karma when client traffic is detected
                    self.hopper.increase_karma()

                data['tags'] = list(data['tags'])
                self.db.frames.add(data)
            now = time()
            took = now - start

            if stat_prev + stat_every < now:
                took = time() - sniff_begin
                print "STAT: pkts=%d t_total=%.2fs pps=%.2f swipes=%d avg_swipe_t=%.2f cur_ch=%d" % (
                    pkts_all, took,
                    pkts_all / took,
                    self.hopper.swipes_total,
                    took/(self.hopper.swipes_total + 0.001),
                    self.hopper.channel_number,
                )
                stat_prev = now

            if self.enable_hopping:
                ret = self.hopper.karmic_hop()
                if ret is False:
                    break

            self.watchdog.dontkillmeplease()
