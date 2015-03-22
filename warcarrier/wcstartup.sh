#!/bin/bash
## THIS IS SOLELY FOR AUTO STARTING IN WARCARRIEROS AND WEAKERTH4N ##
if [ $(iwconfig | grep mon0 | wc -l) -lt 1 ]; then airmon-ng start wlan0; fi;
if [ $(ps aux | grep -i gps[d] | wc -l) -lt 1 ]; then gpsd /dev/ttyUSB0; fi;
