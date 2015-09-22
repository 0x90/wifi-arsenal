#!/bin/sh

tshark -r ${1} -z io,stat,600,$(tshark -t e -r ${1}  -R "wlan.fcs_good==1 and wlan.fc.type_subtype==0x08" | grep -o -e '\(SSID=["]*\(\S*\)["]*\)' | sort | uniq | cut -d'"' -f2 | awk '{printf("%swlan_mgt.tag.interpretation==\"%s\"",sep,$1);sep=","}') -q

