#!/usr/bin/env python
import zipfile
from canari.easygui import multenterbox
from common.entities import Database, ZipFile
from canari.maltego.utils import debug, progress
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
    label='Watcher - Zip database file',
    description='Zip the watcher database to a specified location',
    uuids=[ 'Watcher.v2.zip_db_2_file' ],
    inputs=[ ( 'Watcher', Database ) ],
    debug=False
)
def dotransform(request, response):

    db_file = request.value

    msg = 'Enter output filename (including path)'
    title = 'Watcher - Zip database'
    fieldNames = ["File Name"]
    fieldValues = []
    fieldValues = multenterbox(msg, title, fieldNames)

    save_file = fieldValues[0]

    zip_out = zipfile.ZipFile(save_file, 'w')
    zip_out.write(db_file)
    zip_out.close()

    e = ZipFile(save_file)
    response += e
    return response
