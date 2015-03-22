#!/bin/bash
killall wicd
killall dhclient
killall wpa_supplicant
killall wpa_cli
killall ifplugd

ifconfig $1 down
