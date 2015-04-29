#!/usr/bin/env python
import os
from common.entities import MonitorInterface
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
    label='Watcher - Delete Database',
    description='Deletes Watcher database',
    uuids=[ 'Watcher.v2.delete_db' ],
    inputs=[ ( 'Watcher', MonitorInterface ) ],
    debug=False
)
def dotransform(request, response):

    watcher_db = 'Watcher/resources/databases/watcher.db'

    try:
        if os.path.isfile(watcher_db) == False:
            return response + UIMessage('Database doesnt exist, please run Watcher - Create Database transform')
        else:
            os.remove(watcher_db)
            return response + UIMessage('Database deleted...!!!')
    except:
        pass

    

    
