#!/bin/sh

if grep -q ath[0-9]: /proc/net/dev;then
	BASE=wifi0
	if [ -n "$1" ] && [ -z "${1#wifi[0-9]}" ];then
		BASE=$1
		shift
	fi
	WLDEV=mon0
	wlanconfig $WLDEV create wlandev $BASE wlanmode monitor >/dev/null
	ip link set dev $WLDEV up
	horst -i $WLDEV $*
	ip link set dev $WLDEV down
	wlanconfig $WLDEV destroy
else
	if [ -n "$1" ]; then
	    # find the phy for device $1
	    PHY=`iw dev | awk "/phy#[0-9]+/ {phy=\\$1} /Interface/ {if (\\$2 == \"$1\") {sub(\"\#\", \"\", phy); print phy; exit}}"`
	    if [ -n "$PHY" ]; then
		shift
		WLDEV=${PHY}mon0
		iw phy $PHY interface add $WLDEV type monitor flags fcsfail otherbss
		ip link set dev $WLDEV up
		./horst -i $WLDEV $*
		ip link set dev $WLDEV down
		iw dev $WLDEV del
	    else
		horst $*
	    fi
	else
	    horst $*
	fi
fi
