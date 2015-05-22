#!/bin/sh
# Script to prepare an interface for monitoring/packet injection using the
# madwifi-ng drivers
#
# After running this script, use airpwn with -i ath1.

wlanconfig ath1 create wlandev wifi0 wlanmode monitor
ifconfig ath1 up
