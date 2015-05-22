# Author: Tomasz bla Fortuna
# License: GPLv2

import struct
from time import time
import datetime

from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11WEP, Dot11Elt, Dot11
from scapy.layers.dot11 import Dot11ProbeReq, Dot11ProbeResp, Dot11Deauth, Dot11Auth
from scapy.modules import p0f

from fields import *


class PacketParser(object):
    "Helper class used to parse incoming packets"

    def __init__(self, log):
        self.log = log

    def parse(self, p):
        "Parse packet and return metadata dictionary or None if unable to parse"
        data = self._parse_radiotap(p)
        if data is None:
            return

        self._parse_dot11(data, p.payload)

        # DEBUG, not finished
        if p.haslayer('IP'):
            self._parse_highlevel(data, p)

        return data

    def _parse_highlevel(self, data, p):

        ip = p.getlayer('IP')
        # Highlevel meta
        try:
            hl = {
                'src': ip.src,
                'dst': ip.dst,
            }
        except:
            hl = {
                'src': None,
                'dst': None,
            }
            print "Exception"
        data['hl'] = hl
        data['tags'].add('IP')

        tcp = ip.getlayer('TCP')
        udp = ip.getlayer('UDP')
        if tcp is not None:
            ports = [tcp.sport, tcp.dport]
            hl['sport'] = tcp.sport
            hl['dport'] = tcp.dport

            # Additional TCP
            if hl['dport'] == 80:
                # Parse start of HTTP header
                print "QUE", tcp.payload
            if hl['sport'] == 80:
                # Parse start of HTTP response
                print "RES", tcp.payload
            if 443 in ports:
                data['tags'].add('HTTPS')
            if 80 in ports:
                data['tags'].add('HTTP')
        elif udp is not None:
            ports = [udp.sport, udp.dport]
            hl['sport'] = udp.sport
            hl['dport'] = udp.dport

            # TODO: Add DNS query harvesting
            if 53 == udp.dport:
                data['tags'].update(['DNS', 'DNS_REQ'])
                print "DNS QUERY:", repr(ip)
            if 53 == udp.sport:
                data['tags'].update(['DNS', 'DNS_RESP'])

            if 67 == udp.sport or 68 == udp.dport: # BOOTP Server
                data['tags'].update(['BOOTP', 'BOOTP_SERVER'])
            if 67 == udp.dport or 68 == udp.sport: # BOOTP Client
                data['tags'].update(['BOOTP', 'BOOTP_CLIENT'])

        print hl


    def _parse_dot11(self, data, p):
        "Parse Dot11/Dot11Elt layers adding data to dict created during radiotap parse"
        tags = data['tags']

        # http://www.wildpackets.com/resources/compendium/wireless_lan/wlan_packet_types
        dot11 = p.getlayer(Dot11)
        d_type = dot11.type
        d_subtype = dot11.subtype

        tag = None
        if d_type == 0:
            # Management
            tags.add('MGMT')
            tag = mgmt_subtype_tag.get(d_subtype, None)

        elif d_type == 1:
            # Control
            tags.add('CTRL')
            tag = ctrl_subtype_tag.get(d_subtype, None)

        elif d_type == 2:
            # Data
            tags.add('DATA')

            # Alter destination within BSSID for broadcasts
            if data['dst'] == 'ff:ff:ff:ff:ff':
                if data['mac_addr3'] is not None and data['mac_addr3'] != mac_source:
                    print  "SUBS", repr(radiotap)
                    data['dst'] = data['mac_addr3'] # Set from bssid

            return # Nothing more to do with data packet

        # Add tag related to subtype
        if tag:
            tags.add(tag)

        #print "PARSE type=%d subtype=%d %r" % (d_type, d_subtype, repr(p)[:100])
        #print "  ", tags
        #print "  ", repr(p)

        found_vendor = False

        # Recurrent Dot11 parsing
        orig_p = p
        while p:
            p = p.payload

            if type(p) == Dot11Beacon:
                ssid = p.info
                assert p.len == len(ssid)
                if data['ssid'] != None:
                    self.log.info("SSID wasn't None before setting new value ({0} - {1})" % (data['ssid'], ssid))
                data['ssid'] = self._sanitize(ssid)
                continue

            if type(p) != Dot11Elt:
                continue

            if p.ID == ELT_SSID:
                if found_vendor:
                    continue # After vendor, there are dragons

                ssid = p.info
                if p.len != len(ssid):
                    if data['ssid'] is None:
                        print "  Ignoring ssid, wrong length", ssid, d_type, d_subtype, "LEN IS/GIVEN", len(ssid), p.len
                    continue
                if ssid and data['ssid'] is None:
                    ssid = self._sanitize(ssid)
                    data['ssid'] = ssid

            elif p.ID == ELT_DIRECT_SPECTRUM:
                if found_vendor:
                    continue # After vendor, there are dragons
                if p.len != len(p.info) or p.len != 1:
                    msg = "LENGTH %s DOESNT MATCH FOR CHANNEL type/subtype %d/%d" % (p.len, d_type, d_subtype)
                    print msg
                    self.log.info(msg)
                    continue
                if data['channel'] is None:
                    data['channel'] = ord(p.info)
                    if data['channel'] < 0 or data['channel'] > 13:
                        msg = 'Ignoring invalid channel value for type/subtype %d/%d' % (d_type, d_subtype)
                        print msg
                        self.log.info(msg)
                        data['channel'] = None

            elif p.ID == ELT_RSN:
                data['tags'].add('WPA2')

            elif p.ID == ELT_VENDOR:
                found_vendor = True
                if p.info.startswith('\x00P\xf2\x01\x01\x00'):
                    data['tags'].add('WPA')

            elif p.ID == ELT_QOS:
                data['tags'].add('QOS')


    def _sanitize(self, s):
        "Parse SSID fields"
        try:
            x = s.decode('utf-8')
        except:
            x = ''.join([i if ord(i) < 128 else ' ' for i in s])
        return x

    def _parse_radiotap(self, p):
        "Handle data from radiotap header"
        radiotap = p

        # If no source MAC - ignore packet
        if not hasattr(radiotap, 'addr2') or radiotap.addr2 is None:
            return None

        mac_dst = radiotap.addr1
        mac_source = radiotap.addr2
        mac_addr3 = radiotap.addr3
        mac_addr4 = radiotap.addr4

        try:
            if radiotap.notdecoded == '\x00\x00\x00':
                # Probably a self-sent packet - no signal strength for those.
                sig_str = 0
            else:
                sig_str = -(256-ord(radiotap.notdecoded[-4:-3]))
        except:
            self.log.info('Ignoring malformed wifi radiotap header {0!r}', p)
            return None

        antenna = ord(radiotap.notdecoded[-3:-2])

        if sig_str < -120 or sig_str > -5:
            sig_str = None

        try:
            freq = struct.unpack('H', radiotap.notdecoded[-8:-6])[0]
        except:
            freq = None

        broadcast = False

        # Broadcast within some bssid - alter destination
        if mac_dst == 'ff:ff:ff:ff:ff:ff':
            broadcast = True
        # Basic data
        data = {
            'stamp': time(),
            'stamp_utc': datetime.datetime.utcnow(),
            'src': mac_source,
            'dst': mac_dst,
            'strength': sig_str,
            'freq': freq,
            'broadcast': broadcast,

            # Defaults for dot11 parsing
            'ssid': None,
            'channel': None,
            'tags': set(),
        }
        return data
