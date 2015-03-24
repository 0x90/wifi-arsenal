#!/bin/sh

INTERFACE=$1

if [ $# -lt 1 ]; then
    echo "usage: $0 <interface>"
    exit 1
fi

if [ "$OSTYPE" = "FreeBSD" ]; then
    ifconfig $INTERFACE down
    ifconfig $INTERFACE channel 1 mediaopt monitor up
else
    # Assuming MadWiFi because the other drivers suck
    /sbin/ifconfig $INTERFACE down
    /usr/sbin/iwconfig $INTERFACE channel 1 mode monitor essid any
    /sbin/ifconfig $INTERFACE up
fi
