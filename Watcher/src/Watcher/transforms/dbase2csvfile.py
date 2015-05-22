#!/usr/bin/env python
import csv, sqlite3
from canari.easygui import multenterbox
from common.entities import Database, CSVFile
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
    label='Watcher - Export Database to CSV',
    description='Export database to CSV file',
    uuids=[ 'Watcher.v2.export_dbase_2_csv' ],
    inputs=[ ( 'Watcher', Database ) ],
    debug=True
)
def dotransform(request, response):
    
    db_file = request.value

    msg = 'Enter output filename (including path)'
    title = 'Watcher - Export Database to CSV'
    fieldNames = ["File Name"]
    fieldValues = []
    fieldValues = multenterbox(msg, title, fieldNames)

    save_file = fieldValues[0]

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("select * from ssid;")

    csv_writer = csv.writer(open(save_file, 'wt'))
    csv_writer.writerow([i[0] for i in cursor.description])
    csv_writer.writerows(cursor)
    del csv_writer

    e = CSVFile(save_file)
    response += e
    return response
