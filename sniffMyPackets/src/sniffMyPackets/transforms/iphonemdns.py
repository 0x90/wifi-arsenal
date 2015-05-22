#!/usr/bin/env python
import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, MobilePhone
from canari.maltego.message import Field
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
    label='L4 - Find iPhone(s) noisy DNS [SmP]',
    description='Look for MDNS traffic and create a phone entity for it',
    uuids=[ 'sniffMyPackets.v2.phone_from_mdns' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    mdns_dump = []
    phone_info = []

    cmd = 'tshark -r ' + pcap + ' -R "dns.resp.type == 0x0010 && udp.length == 82 && ip.dst == 224.0.0.251" -T fields -e eth.src -e ip.src -e dns.resp.name -e dns.txt -E separator=,'  
    mdns_dump = os.popen(cmd).readlines()
    for x in mdns_dump:
        x = x.split(',')
        phone = x[0], x[1], x[2], x[3]
        if phone not in phone_info:
            phone_info.append(phone)

    for mac, ip, name, model in phone_info:
        for s in re.finditer('(\S*.\S*)..device', name):
            e = MobilePhone(s.group(1))
        e += Field('mac_addr', mac, displayname='MAC Address', matchingrule='loose')
        e += Field('ip_addr', ip, displayname='IP Address', matchingrule='loose')
        for s in re.finditer('model=(\S*)', model):
            e += Field('model', s.group(1), displayname='Phone Model', matchingrule='loose')
        response += e
    return response
