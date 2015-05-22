# Author: Tomasz bla Fortuna
# License: GPLv2

import traceback as tb

from pymongo.errors import InvalidStringData


class Geo(object):
    def __init__(self, db):
        "Geolocation of APs by MACs and ESSIDs"
        self.db = db
        self.geo = self.db['geo']

    def locate(self, mac=None, essid=None):
        "Try to resolve AP position by MAC address"
        where = {}
        if mac is not None:
            mac = mac.lower()
            where['mac'] = mac
        if essid is not None:
            where['essid'] = essid

        results = self.geo.find(where)
        return [ {
            'lat': res['lat'],
            'lon': res['lon'],
            'source': res['s'],
            'essid': res['essid'],
        } for res in results]

    def _index(self):
        print "Creating index"
        self.geo.ensure_index('mac')
        self.geo.ensure_index('essid')

    def load_openwlan(self, path):
        """Load OpenWLAN dataset into MongoDB:
        #wget --no-check-certificate 'https://openwlanmap.org/db.tar.bz2'
        """
        with open(path, 'r') as f:

            print "Clearing OpenWLAN data from DB"
            self.geo.drop_indexes()
            self.geo.remove({'s': 'ow'})
            print "Loading OpenWLAN data"

            # Omit file header
            f.readline()

            cnt = 0
            for line in f:
                x, lat, lon = line.strip().split()
                x = x.lower()
                mac = ":".join([x[0:2], x[2:4], x[4:6], x[6:8], x[8:10], x[10:12]])
                lat, lon = float(lat), float(lon)
                cnt += 1
                obj = {
                    'mac': mac,
                    'essid': None,
                    'lat': lat,
                    'lon': lon,
                    's': 'ow',
                }
                try:
                    self.geo.insert(obj)
                except InvalidStringData:
                    # There are some badly encoded entries there - ignore those.
                    print "Problem at", cnt, "with", x, lat, lon
                    tb.print_exc()
                if cnt % 50000 == 0:
                    print "Read", cnt

        self._index()
