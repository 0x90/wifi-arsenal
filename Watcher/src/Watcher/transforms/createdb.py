#!/usr/bin/env python
import os
import sqlite3 as lite
from common.entities import Database, MonitorInterface
from canari.maltego.message import UIMessage
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Watcher Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]

#@superuser
@configure(
    label='Watcher - Create Database',
    description='Creates the Watcher Database and Tables',
    uuids=[ 'Watcher.v2.create_db_tables' ],
    inputs=[ ( 'Watcher', MonitorInterface ) ],
    debug=False
)
def dotransform(request, response):

    watcher_db = 'Watcher/resources/databases/watcher.db'

    try:
        if os.path.isfile(watcher_db) == True:
            return response + UIMessage('Database already exists, please run "Watcher - Delete Database" transform')
    except:
        pass

    con = lite.connect(watcher_db)

    with con:
        cur = con.cursor()
        cur.execute('CREATE TABLE ssid(tdate TEXT, ttime TEXT, ssid TEXT, mac TEXT, iface TEXT);')
        cur.execute("CREATE TABLE aplist(tdate TEXT, ttime TEXT, ssid TEXT, bssid TEXT, channel INT, enc TEXT, rssi TEXT, iface TEXT)")

    e = Database(watcher_db)
    response += e
    con.close()
    return response
