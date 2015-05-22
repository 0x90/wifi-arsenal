#!/usr/bin/env python
import sqlite3 as lite
from common.entities import WirelessClient, Vendor
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
    label='Watcher - MAC Address Lookup',
    description='Tries to work out the vendor from the MAC address',
    uuids=[ 'Watcher.v2.client_2_manufacturer' ],
    inputs=[ ( 'Watcher', WirelessClient ) ],
    debug=True
)
def dotransform(request, response):

    mac_addr = request.value[:-9].upper()
    mac_addr = mac_addr.replace(':', '')
    mac_db = 'Watcher/resources/databases/macaddr.db'
    mac_vendor = []

    con = lite.connect(mac_db)
    with con:
        cur = con.cursor()
        cur.execute('SELECT * FROM macaddr WHERE mac like ' + "\"" + mac_addr + "\"")
        while True:
            row = cur.fetchone()
            if row == None:
                break
            if row[1] not in mac_vendor:
                mac_vendor.append(row[1])

    for x in mac_vendor:
        e = Vendor(x)
        response += e
    return response