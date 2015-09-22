#!/bin/sh

MONITOR="mon0"
INTERFACE="phy phy0"
iw dev $MONITOR info 2>/dev/null 1>/dev/null
if [ $? -ne 0 ]; then
	echo "creating monitor interface $MONITOR"
	iw $INTERFACE interface add $MONITOR type monitor
else
	echo "error: $MONITOR already exists"
fi

ifconfig $MONITOR up
