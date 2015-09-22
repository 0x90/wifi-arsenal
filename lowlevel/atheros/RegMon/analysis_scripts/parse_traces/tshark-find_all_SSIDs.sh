#!/bin/bash
#
# list all uniqui SSIDs that are in the wireless trace give in $1
#

TRACE=$1

tshark -r $TRACE "wlan.fc.type_subtype==0x08 && radiotap.flags.badfcs == 0" | grep -o -e '\(SSID=["]*\(\S*\)["]*\)' | sort | uniq
