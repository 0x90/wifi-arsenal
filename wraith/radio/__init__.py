#!/usr/bin/env python

""" radio: 802.11 network interface objects and functions

Objects/functions to manipulate wireless nics and parse 802.11 captures.
Partial support of 802.11-2012
Currently Supported
802.11a\b\g

Partially Supported
802.11n

Not Supported
802.11s\y\ac\ad\af

REVISIONS:
radio 0.0.5
 desc: provides tools to manipulate wireless nics and parse raw wireless traffic
 includes: bits 0.0.4 channels 0.0.1, mcs 0.0.1, iw 0.1.0 iwtools 0.0.12,
 radiotap 0.0.4, mpdu 0.1.0, infoelement 0.0.1, oui 0.0.1
 changes:
  - cleaned up some of the code in mpdu
    o moved parse function to top, 'sectioned' code together based on field,
      type of frame
    o defined a 'wrapper' class around the mpdu dict
    o added wep, tkip and ccmp parsing
    o decided to pass on parsing msb of qosctrl to 'clients'
  - modified regget in iw to allow partial parsing of regulatory domain

TODO:
 1) Should we add support for AVS, Prism headers ?
 2) radiotap: ensure data pad is handled for atheros cards (any others?)
 3) mpdu: fully parse
    - control wrapper
    - +htc
    - info-elements
     o RSN Std 8.4.2.27 (Info-Element # 48
     o TIM Info-Element # 5
 5) how to support a-msdu etc
 6) 802.1X parsing as well as additional mpdu i.e. 802.11u, 802.11s etc
"""
__name__ = 'radio'
__license__ = 'GPL v3.0'
__version__ = '0.0.4'
__date__ = 'Janurary 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'