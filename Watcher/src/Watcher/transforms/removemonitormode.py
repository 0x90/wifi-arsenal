#!/usr/bin/env python
import os
from common.entities import MonitorInterface
from canari.maltego.message import UIMessage
from canari.framework import configure, superuser

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


@superuser
@configure(
    label='Watcher - Set interface to normal',
    description='Removes monitor mode from an interface',
    uuids=[ 'Watcher.v2.remove_monitor_mode' ],
    inputs=[ ( 'Watcher', MonitorInterface ) ],
    debug=False
)
def dotransform(request, response):

    iface = request.value

    cmd = 'airmon-ng stop ' + iface + ' && service network-manager start'
    s = os.popen(cmd).readlines()
    return response + UIMessage('Monitor mode disabled..!!')
