#!/bin/sh
# Script to prepare an interface for monitoring/packet injection using
# mac80211-based drivers
#
# After running this script, use airpwn with -i mon0.

iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
