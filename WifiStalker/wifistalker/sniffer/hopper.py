# Author: Tomasz bla Fortuna
# License: GPLv2

import os
import sys
from collections import defaultdict
from time import time, sleep

from wifistalker import pythonwifi

from wifistalker import config


class Hopper(object):
    """
    Handle all logic regarding channel hopping.
    """
    def __init__(self, log, base_interface, related_interface):
        self.log = log
        self.base_interface = base_interface
        self.related_interface = related_interface

        self.wifi = None
        self.reset_interface()

        self.tries = 10
        self.config = config.hopper

    def __del__(self):
        del self.wifi

    def reset_interface(self):
        "Reset interface"
        if self.wifi is not None:
            del self.wifi
        if self.related_interface:
            self.log.info("Putting related interface (%s) down" % self.related_interface)
            os.system('ifconfig %s down' % self.related_interface)
        self.wifi = pythonwifi.Wireless(self.base_interface)


    def configure(self, use_24=True, use_pop5=False):
        # TODO: Optimize? Fix - add rest, + 5GHz option

        self.freqs = {
            1: '2.412GHz',
            2: '2.417GHz',
            3: '2.422GHz',
            4: '2.427GHz',
            5: '2.432GHz',
            6: '2.437GHz',
            7: '2.442GHz',
            8: '2.447GHz',
            9: '2.452GHz',
            10: '2.457GHz',
            11: '2.462GHz',
            12: '2.467GHz',
            13: '2.472GHz',

            36: '5.180GHz',
            40: '5.200GHz',
            44: '5.220GHz',
            48: '5.240GHz',
            #(14, '2.484 Ghz'), # 14
        }

        # 5Mhz gap, 22MHz wide band.
        # Hopping: 1,6,11; (+2) 3,8,13; (+1) 2,7,12; (+3); 4,10,[14],5,9
        self.channels_24 = [
            1,6,11, 3,8,13, 2,7,12, 4,10,5,9
        ]

        # Popular 5GHz channels:
        # 36 (5.18GHz), 40 (5.2), 44, 48
        self.channels_5pop = [
            36, 40, 44, 48
        ]

        self.channels = self.channels_24 if use_24 else []
        if use_pop5:
            self.channels += self.channels_5pop

        if not self.channels:
            print "ERROR: No channels selected for hopping"
            return False

        self.hop_failures = defaultdict(lambda: 0)
        self.hop_total = 0
        self.swipes_total = 0

        self.channel_idx = 0
        self.channel_number = -1 # Not yet known in fact
        self.channel_cnt = len(self.channels)
        self.channel_karma = 0
        self.channel_inc = 0
        self.took = 0
        self.channel_swipe_start = time()
        return True

    def increase_karma(self):
        "Current channel is nice - stay here longer"
        if self.channel_inc > self.config['max_karma']:
            return
        self.channel_karma += 1
        self.channel_inc += 1

    def hop(self):
        "Unconditional channel hop"
        self.channel_karma = 0
        self.channel_inc = 0

        start = time()

        # Increment channel
        self.channel_idx = (self.channel_idx + 1) % self.channel_cnt
        self.channel_number = self.channels[self.channel_idx]
        freq = self.freqs[self.channel_number]

        if self.channel_idx == 0:
            took = time() - self.channel_swipe_start
            self.swipes_total += 1
            self.channel_swipe_start = time()

        # Tries must fit within watchdog limit.
        for i in range(0, self.tries):
            try:
                self.wifi.setFrequency(freq)
                self.hop_total += 1
                return True
            except IOError:
                self.log.info('Try {0}/{1}: Channel hopping failed (f={1} ch={2})', i+1, self.tries,
                              freq, self.channel_number)
                self.hop_failures[self.channel_number] += 1
                self.reset_interface()
                sleep(0.8)

        self.log.info('Failure after %d failed hopping tries' % i)
        if self.related_interface is None:
            self.log.info('Try setting related interface')

        return False


    def karmic_hop(self):
        "Hop to the next channel, take karma into account"
        if self.channel_karma:
            self.channel_karma -= 1
            print 'Staying a bit longer on {2}; karma={0} karma_inc={1}'.format(self.channel_karma,
                                                                                self.channel_inc,
                                                                                self.channel_number)
            return True

        return self.hop()
