#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# meerkat.probes.wifi_client_scan
#
# Copyright 2012 Konrad Markus
#
# Author: Konrad Markus <konker@gmail.com>
#

import sys
import json
import array
from scapy.all import *

MANAGEMENT_FRAME_TYPE = 0
#MANAGEMENT_FRAME_SUBTYPES = (0, 2, 4)
MANAGEMENT_FRAME_SUBTYPES = (8,)

#unique = []
iface  = 'mon0'


def main():
    sniff(iface=iface, prn=sniffCallback)


def sniffCallback(p):
    if p.haslayer(Dot11):
        if p.type == MANAGEMENT_FRAME_TYPE and \
                p.subtype in MANAGEMENT_FRAME_SUBTYPES:
            print(p.show2())

if __name__ == '__main__':
    main()
