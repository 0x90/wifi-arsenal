#!/usr/bin/env python

import argparse
import time
import os
import sys

# "interesting" stats to grab from debugfs
STATS = ('dot11FCSErrorCount', 'received_fragment_count')

DEFAULT_RUN_LENGTH = 60 * 10  # seconds
INTERVAL = 0.1                # seconds
DEBUGFS = '/sys/kernel/debug/ieee80211'

try:
    ifaces = sorted(os.listdir(DEBUGFS))
except OSError as err:
    sys.stderr.write('{}\n'.format(str(err)))
    sys.exit(1)

ap = argparse.ArgumentParser()
ap.add_argument('-t', '--time', type=int, default=DEFAULT_RUN_LENGTH,
        help='How long in seconds to collect data (default {})'.format(DEFAULT_RUN_LENGTH))
ap.add_argument('-i', '--interface', choices=ifaces, default=ifaces[0],
        help='Interface to monitor (default {})'.format(ifaces[0]))
ap.add_argument('outfile', type=str, help='Output file (CSV)')
args = ap.parse_args()

phyfiles  = ['{}/{}/statistics/{}'.format(DEBUGFS, args.interface, x) for x in STATS]
starttime = time.time()
endtime   = starttime + args.time

with open(args.outfile, 'w') as outf:
    outf.write('time_seconds,{}\n'.format(','.join(STATS)))
    while True:
        t = time.time()
        if t > endtime:
            break

        ctrvals = [open(p).read().rstrip() for p in phyfiles]
        outf.write('{},{}\n'.format(t, ','.join(ctrvals)))
        time.sleep(INTERVAL)
