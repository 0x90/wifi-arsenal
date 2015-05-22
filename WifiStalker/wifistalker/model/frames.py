# Author: Tomasz bla Fortuna
# License: GPLv2

from wifistalker import config
from time import time

class Frames(object):
    """Low-level frame data model - object keeps sniffed pkts metadata.

    Frames are split into
    - current_frames - all received metadata, but automatically removed after (by default) 2 hours.
    - all_frames - never automatically purged collection, but in fact - filtered. Repeated, similar
                   beacons are not stored.
    """

    def __init__(self, db):
        self.db = db
        # All received packets ever, but with beacon filter
        self.all_frames = self.db['all_frames']
        self.all_frames.ensure_index('stamp')
        self.all_frames.ensure_index('src')

        # Current frames - all within a time window
        self.current_frames = self.db['current_frames']
        self.current_frames.ensure_index('stamp_utc', expireAfterSeconds=2*60*60)
        self.current_frames.ensure_index('stamp')
        self.current_frames.ensure_index('mac')

        # Data for beacon filter; (mac, ssid) -> {last seen stamp, last stored str, cur averaged str}
        self.beacons = {}
        self.last_cleanup = time()
        self.beacons_omitted = 0
        self.beacons_stored = 0
        self.frames_checked = 0

    def _beacon_filter(self, frame):
        "Returns False to omit a frame, and True to include it"
        cfg = config.beacon_filter

        self.frames_checked += 1
        if 'BEACON' not in frame['tags']:
            # Not a beacon
            return True

        # Clear cache from stale entries
        now = time()
        if now > self.last_cleanup + cfg['cleanup_interval']:
            self.last_cleanup = now
            for key in self.beacons.keys():
                entry = self.beacons[key]
                if now > entry['stamp'] + cfg['max_time_between']:
                    del self.beacons[key]

        # Read from cache
        key = (frame['src'], frame['ssid'])
        cache = self.beacons.get(key, None)
        if not cache:
            self.beacons[key] = {
                'stamp': frame['stamp'],
                'stored_str': frame['strength'],
                'avg_str': frame['strength'],
            }
            self.beacons_stored += 1
            return True

        def update_cache():
            cache['stored_str'] = frame['strength']
            cache['stamp'] = frame['stamp']
            self.beacons_stored += 1

        # Update str
        cache['avg_str'] = (cache['avg_str'] * 5.0 + frame['strength']) / 6.0

        if abs(cache['avg_str'] - cache['stored_str']) >= cfg['max_str_dev']:
            update_cache()
            return True

        # Check time
        if cache['stamp'] + cfg['max_time_between'] < frame['stamp']:
            update_cache()
            return True

        self.beacons_omitted += 1
        return False

    def add(self, frame):
        "Add frame to database"
        #self.all_frames.insert(metadata)
        try:
            self.current_frames.insert(frame)
            if self._beacon_filter(frame):
                self.all_frames.insert(frame)
        except:
            print "Frame storage failed on:"
            print repr(frame)
            raise

        # Print filter stats
        if self.frames_checked % 100 == 0:
            self.db.log.info("Beacon filter: filtered={0:.2f}% omitted={1} stored={2} checked={3} cache_size={4}",
                             100.0 * self.beacons_omitted/(self.beacons_omitted + self.beacons_stored + 0.1),
                             self.beacons_omitted, self.beacons_stored, self.frames_checked,
                             len(self.beacons))

    ##
    # Querying
    def iterframes(self, current=True, src=None, since=None, sort='stamp'):
        "Iterate over frames"
        if current:
            source = self.current_frames
        else:
            source = self.all_frames

        direction = 1
        if sort.startswith('-'):
            direction = -1
            sort = sort[1:]

        where = {}
        if since is not None:
            where['stamp'] = {'$gte': since}
        if src:
            if isinstance(src, list):
                src = [s.lower() for s in src]
                where['src'] = {'$in': src}
            else:
                src = src.lower()
                where['src'] = src

        frames = source.find(where).sort(sort, direction)
        for frame in frames:
            yield frame

