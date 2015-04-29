#!/usr/bin/env python
import requests
import re
from canari.config import config
from common.entities import SSID
from canari.maltego.entities import Image
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
    label='Watcher - SSID to Google Map',
    description='Uses Wigle.net to try and get Map of SSID location',
    uuids=[ 'Watcher.v2.ssid_2_googlemap' ],
    inputs=[ ( 'Watcher', SSID ) ],
    debug=True
)
def dotransform(request, response):
    
    ssid = request.value

    username = config['wigle/username'].strip('\'')
    password = config['wigle/password'].strip('\'')
    
    w_login = 'https://wigle.net/gps/gps/main/login'
    w_query = 'https://wigle.net/gps/gps/main/confirmquery/'
    gurl_base = 'http://maps.googleapis.com/maps/api/streetview?size=800x800&sensor=false&location='

    map_details = []
    
    def Wigle_SSID(username, password, ssid):
    # Create a session with requests to enable the use of auth cookies
        agent = requests.Session()
    
    # Login to Wigle.net using the specified creds
        agent.post(w_login, data={'credential_0': username, 'credential_1': password, 'destination': '/gps/gps/main'})
    
    # Submit query against the MAC address of the AP (confirmlocquery, netid)
        response = agent.post(url=w_query, data={'ssid': ssid,'Query': 'Query'})
    # Pull the latitude and longitude from the raw response
        for s in re.finditer(r'maplat=(\S*)&maplon=(\S*)&map', response.text):
            lat = s.group(1)
            lng = s.group(2)
    
    # Build the Google Maps URL
            gurl = gurl_base + str(lat) + ',' + str(lng)
            mapping = str(lat), str(lng), gurl
    
    # Add the details to a variable for creating the entity
            if mapping not in map_details:
                map_details.append(mapping)
    
    Wigle_SSID(username, password, ssid)
    
    for x in map_details:
        cords = 'Lat: ' + str(x[0]).strip('\'') + '\nLong: ' + str(x[1]).strip('\'')
        e = Image(cords)
        e.url = x[2]
        response += e
    return response