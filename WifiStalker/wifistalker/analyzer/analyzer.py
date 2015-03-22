# -!- coding: utf-8 -*-

# Author: Tomasz bla Fortuna
# License: GPLv2

from pprint import pprint
from time import time, sleep
from collections import defaultdict

from wifistalker.model import Sender, SenderCache
from wifistalker import Log, WatchDog

class Analyzer(object):
    """Handle packet analysis.

    TODO: Split into two classes - one doing analysis, second with generic analysis logic.
    """
    def __init__(self, db):
        self.db = db

        # Cache modified senders
        self.sender_cache = SenderCache(db)

        # Logging
        self.log = Log(self.db, use_stdout=True, header='ANALYZE')

        # Keeps me running if started correctly (bash loop, or device
        # reboot loop - for embedded)
        self.watchdog = WatchDog(interval=20)

        self.stats = {
            'already_analyzed': 0,
            'analyzed': 0,
        }

    def _analyze_frame(self, sender, frame):
        "Analyze a single frame and update sender object accordingly"

        tags = set(frame['tags'])

        aggregate = sender.aggregate # Alias
        stat = sender.stat # Alias

        if aggregate['last_seen'] >= frame['stamp']:
            # We already updated sender using this frame
            self.stats['already_analyzed'] += 1
            return

        aggregate['last_seen'] = frame['stamp']
        if aggregate['first_seen'] == 0:
            aggregate['first_seen'] = frame['stamp']

        # Handle Tags
        if tags:
            x = set(aggregate['tags'])
            x.update(tags)
            aggregate['tags'] = list(x)

        if 'ASSOC_REQ' in tags:
            stat['assoc_req'] += 1
        elif 'ASSOC_RESP' in tags:
            stat['assoc_resp'] += 1
        elif 'PROBE_REQ' in tags:
            stat['probe_req'] += 1
        elif 'PROBE_RESP' in tags:
            stat['probe_resp'] += 1
        elif 'DISASS' in tags:
            stat['disass'] += 1
        elif 'BEACON' in tags:
            stat['beacons'] += 1
        elif 'DATA' in tags:
            stat['data'] += 1
        elif 'IP' in tags:
            stat['ip'] += 1

        stat['all'] += 1

        # Handle SSIDs and destinations
        ssid = frame['ssid']
        if ssid:
            if 'BEACON' in tags:
                if ssid not in aggregate['ssid_beacon']:
                    aggregate['ssid_beacon'].append(ssid)
            elif 'PROBE_REQ' in tags:
                if ssid not in aggregate['ssid_probe']:
                    aggregate['ssid_probe'].append(ssid)
            else:
                # Not Beacon, not probe, something else.
                if ssid not in aggregate['ssid_other']:
                    aggregate['ssid_other'].append(ssid)
                """
                if sender.meta['ap']:
                    # This is rather a beacon...
                    if ssid not in aggregate['ssid_beacon']:
                        aggregate['ssid_beacon'].append(ssid)
                else:
                    # Or not?
                    if ssid not in aggregate['ssid_other']:
                        aggregate['ssid_other'].append(ssid)
                """


        if frame['dst']:
            sender.add_dst(frame['dst'], tags)

        if frame['strength']:
            sender.meta['running_str'] = (sender.meta['running_str'] * 10.0 + frame['strength']) / 11.0

        # Is it an AP or a client?
        # Phone can send beacons. But APs can send probes too.
        if (stat['probe_req'] > 0
            and len(aggregate['ssid_probe']) > len(aggregate['ssid_beacon'])):
            sender.meta['ap'] = False
        elif stat['beacons'] > 0:
            sender.meta['ap'] = True


        """
        seen = {
            'stamp': frame['stamp'],
            'dst': frame['dst'],
            'freq': frame['freq'], # TODO: Remove?
            'str': frame['strength'],
            'tags': frame['tags']
        }
        """
        self.stats['analyzed'] += 1
        #sender.update_events(seen)

    def _analysis_loop(self, current, since):
        "Analyze until all senders got updated"
        only_src_macs = [] # Any at start
        last_stamp = None
        frames_total = 0

        # Repeat this iterator until all senders are correctly saved.
        while True:
            iterator = self.db.frames.iterframes(current=current,
                                                 since=since,
                                                 src=only_src_macs)
            # Go throught the iterator
            cnt = 0
            for cnt, frame in enumerate(iterator):
                src = frame['src']
                sender = self.sender_cache.get(src)
                if sender is None:
                    sender = self.sender_cache.create(src)
                self._analyze_frame(sender, frame)
                last_stamp = frame['stamp']
                if (cnt+1) % 10000 == 0:
                    now = time()
                    print "Done {0} frames, last is {1} seconds ago;".format(cnt+1, now-last_stamp)
                    self.watchdog.dontkillmeplease()
            s = "Analyzed {0} frames, last stamp is {1}; Analyzed total={2[analyzed]}"
            frames_total += cnt
            print s.format(cnt, last_stamp, self.stats)

            if last_stamp is None:
                # No frames whatsoever
                return None

            # Update statics before storing
            for mac, sender in self.sender_cache.iteritems():
                self._update_static(sender)

            # Try to save
            only_src_macs = self.sender_cache.store()

            if not only_src_macs:
                # Everything saved succesfully
                return (last_stamp, frames_total)

            # Not everything saved, continue until everything is
            # written.
            self.log.info('Optimistic locking failed, analysis retry for %r', only_src_macs)


    def run_full(self):
        "Full data drop + reanalysis"

        # TODO - Drop in soft mode
        print 'Dropping existing knowledge in...'
        for i in range(3, 0, -1):
            print i, "second/s"
            sleep(1)
        #self.db.knowledge.sender_drop()

        senders = self.db.knowledge.sender_query()
        for sender in senders:
            sender.reset(hard=False)
            self.db.knowledge.sender_store(sender)

        # Once
        self._analysis_loop(current=False, since=0)


    def run_continuous(self):
        "Continuous analysis"
        self.log.info('Starting continuous analysis')

        # One-time update for all knowledge entries
        #self._one_time_update()

        # Reduce CPU usage by analyzing more frames in one go while
        # trying to keep this number low to get frequent updates for
        # the UI.
        interval = 3

        # `since' creates a moving point-of-time from which we read frames.
        # Initialize with timestamp of last analysis
        result = self.db.knowledge.sender_query(count=1, sort='-aggregate.last_seen')
        if result:
            since = result[0].aggregate['last_seen'] - 1
        else:
            since = 0

        print "Starting from ", time() - since, "seconds in the past"

        while True:
            self.watchdog.dontkillmeplease()

            # Read current frames
            ret = self._analysis_loop(current=True, since=since)

            # Try to analyze 150 - 250 frames in one pass
            new_since, frames_total = ret if ret else (since, 0)
            if frames_total < 150 and interval < 10:
                interval += 0.5
                print "interval is", interval
            if frames_total > 250 and interval > 1:
                interval -= 1 if interval > 1 else 0.1
                print "interval is", interval

            self.watchdog.dontkillmeplease()
            sleep(interval)
            since = new_since



    def _update_static(self, sender):
        # Decode vendor
        sender.meta['vendor'] = self.db.knowledge.get_vendor(sender.mac)

        # Decode GEO location based on bssid/mac
        locations = self.db.geo.locate(mac=sender.mac)
        for loc in locations:
            sender.add_geo(loc)


    def _one_time_update(self):
        raise Exception()

        senders = db.get_knowledge()
        self._update_geo(senders)
        for mac, sender in senders.iteritems():
            # TODO: Don't update if nothing changed
            sender['version'] += 1
            ret = db.set_sender(sender)
        print "One time update finished", len(senders)
