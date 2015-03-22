#!/usr/bin/env python
# -*- coding: Utf-8 -*-

# Configuration for rspoof.py
# All directories must end in backslash, no validation implemented

# Path to the rspoof root
RSPOOF_PATH = "/usr/share/rspoof/"

# The path the the apache document root
WEBROOT_PATH = "/var/www/"

# Enter the primary interface capable of monitor mode and injections.
PRIMARY_WLAN_INTERFACE = "wlan0"

# If you have a secondary wireless card, us it here, it'll improve performance.
SECONDARY_WLAN_INTERFACE = "wlan0"

# This is the IP that is registered in DHCP for your localhost. Leave this if you don't know what it does.
LOCALHOST_IP = "192.168.1.129"