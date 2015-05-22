#!/usr/bin/env python
import sqlite3 as lite
from common.entities import Vendor, MacAddress
from canari.maltego.message import Field
from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2014, Sniffmypackets Project'
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
    label='L3 - MAC Address to Vendor',
    description='Tries to resolve MAC address to hardware vendor',
    uuids=[ 'sniffMyPackets.v2.MacAddress_2_Vendor' ],
    inputs=[ ( 'sniffMyPackets', MacAddress ) ],
    debug=False
)
def dotransform(request, response):
    
    mac_addr = request.value[:-9].upper()
    mac_addr = mac_addr.replace(':', '')
    mac_db = 'sniffMyPackets/resources/databases/utilities.db'
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