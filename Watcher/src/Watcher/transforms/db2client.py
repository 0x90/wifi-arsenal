#!/usr/bin/env python
import sys
import sqlite3 as lite
from common.entities import MonitorInterface, WirelessClient
from canari.maltego.message import Field, UIMessage
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
    label='Watcher - Maps Clients',
    description='Maps wireless clients from the database',
    uuids=[ 'Watcher.v2.db_2_wirelessclient' ],
    inputs=[ ( 'Watcher', MonitorInterface ) ],
    debug=False
)
def dotransform(request, response):

    # Setup the sqlite database connection
    watcher_db = 'Watcher/resources/databases/watcher.db'
    con = lite.connect(watcher_db)

    client_list = []

    ssid = request.value

    with con:
        cur = con.cursor()
        cur.execute('SELECT * FROM ssid')
        while True:
            row = cur.fetchone()
            if row == None:
                break
            if row[3] not in client_list:
                client_list.append(row[3])

    for x in client_list:
        e = WirelessClient(x)
        response += e
    return response
