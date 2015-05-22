#!/usr/bin/env python

import pygeoip, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import Location
from canari.maltego.message import Field, UIMessage, Label
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
    label='L4 - IP Address to GeoLoc [SmP]',
    description='Searchs pcap file and performs GeoIP Lookup',
    uuids=[ 'sniffMyPackets.v2.ip_2_geolocation' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    # Download GeoIP Database from MaxMinds
    if not os.path.exists('/opt/geoipdb/geoipdb.dat'): 
        return response + UIMessage('Need local install of MaxMinds Geo IP database, use the download script in resource/external/geoipdownload.sh')

    gi = pygeoip.GeoIP('/opt/geoipdb/geoipdb.dat')

    pcap = request.value
    pkts = rdpcap(pcap)

    ip_raw = []
    ip_geo = []
    ip_exclusions = ['192.168.', '172.16.', '10.']

    for x in pkts:
        if x.haslayer(IP):
            src = x.getlayer(IP).src
            if src != '0.0.0.0':
                if src not in ip_raw:
                    ip_raw.append(src)

    for s in ip_raw:
        if ip_exclusions[0] in s or ip_exclusions[1] in s or ip_exclusions[2] in s:
            pass
        else:
            rec = gi.record_by_addr(s)
            city = rec['city']
            postcode = rec['postal_code']
            country = rec['country_name']
            lng = rec['longitude']
            lat = rec['latitude']
            ccode = rec['country_code']
            google_map_url = 'https://maps.google.co.uk/maps?z=20&q=%s,%s' %(lat, lng)
            geo_ip = s,city, postcode, country, ccode, str(lng), str(lat), google_map_url
            if geo_ip not in ip_geo:
                ip_geo.append(geo_ip)

    for ip, city, postcode, country, ccode, lng, lat, gmap in ip_geo:
        e = Location(country)
        e.country = country
        e.city = city
        e.linkcolor = 0x2314CA
        e.linklabel = ip
        e.areacode = postcode
        e.longitude = float(lng)
        e.latitude = float(lat)
        e.countrycode = ccode
        e += Field('ipaddress', ip, displayname='IP Address')
        e += Field('geomapurl', gmap, displayname='Google Map URL')
        e += Field('pcapsrc', pcap, displayname='Original pcap File')
        response += e
    return response
