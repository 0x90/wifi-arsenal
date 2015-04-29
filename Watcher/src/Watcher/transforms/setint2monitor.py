#!/usr/bin/env python
import os, re
from common.entities import Interface, MonitorInterface
from canari.framework import configure , superuser

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
    label='Watcher - Set interface into Monitor Mode',
    description='Sets your specified interface into monitor mode',
    uuids=[ 'Watcher.v2.setint_2_monitor' ],
    inputs=[ ( 'Watcher', Interface ) ],
    debug=False
)
def dotransform(request, response):

    iface = request.value
    set_m_mode = 'airmon-ng check kill && airmon-ng start %s' % (iface)
    s = os.popen(set_m_mode).readlines()
    for x in s:
        if 'monitor mode enabled' in x:
            for t in re.finditer('monitor mode enabled on (\w*)', x):
                e = MonitorInterface(t.group(1))
                response += e
            return response