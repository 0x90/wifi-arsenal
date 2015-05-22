#!/usr/bin/env python
import csv
import sqlite3 as lite
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import Host, Service
from canari.maltego.message import Field, Label, UIMessage
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
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
    label='L2 - Identify Service [SmP]',
    description='Looks to match a service to a port',
    uuids=[ 'sniffMyPackets.v2.identify_2_service' ],
    inputs=[ ( 'sniffMyPackets', Host ) ],
    debug=False
)
def dotransform(request, response):
    
    svc_db = 'sniffMyPackets/resources/databases/utilities.db'
    pcap = request.fields['pcapsrc']
    dport = request.fields['sniffMyPackets.hostdport']
    proto = request.fields['proto']

    service = []

    con = lite.connect(svc_db)
    with con:
        cur = con.cursor()
        cur.execute('SELECT * FROM services WHERE port like ' + "\"" + dport + "\"" + ' AND proto like ' + "\"" + proto + "\"")
        while True:
            row = cur.fetchone()
            if row == None:
                break
            if row[0] not in service:
                service.append(row[0])

    for s in service:
        e = Service(s)
        e.linklabel = proto + ':' + dport
        e.linkcolor = 0x0B615E
        e += Field('pcapsrc', pcap, displayname='Original pcap File')
        e += Field('id_dport', dport, displayname='Original Destination port')
        response += e
    return response