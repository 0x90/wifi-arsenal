#!/usr/bin/env python

""" oui.py: oui/manuf related functions

Parse the 802.11 MAC Protocol Data Unit (MPDU) IAW IEED 802.11-2012
we use Std when referring to IEEE Std 802.11-2012
NOTE:
 It is recommended not to import * as it may cause conflicts with other modules
"""

__name__ = 'oui'
__license__ = 'GPL v3.0'
__version__ = '0.0.1'
__date__ = 'January 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import re

def parseoui(path):
    """ parse aircrack-ng oui file at path filling in oui dict oui->manuf """
    fin = None
    oui = {}
    pattern = r'^([-|\w]*)   \(hex\)\t\t(.*)\r'
    try:
        fin = open(path)
        for line in fin.readlines():
            found = re.search(pattern,line)
            try:
                m = found.group(2)
                if m.startswith('IEEE REGISTRATION AUTHORITY'):
                    m = 'IEEE REGISTRATION AUTHORITY'
                oui[(found.group(1).replace('-',':')).lower()] = m[:100]
            except AttributeError:
                pass
        fin.close()
    except IOError:
        if fin and not fin.closed: fin.close()
    return oui

def manufacturer(oui,mac):
    """ returns the manufacturer of the mac address if exists, otherwise 'unknown' """
    try:
        return oui[mac[:8]]
    except KeyError:
        return "unknown"