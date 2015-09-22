#!/bin/sh

tshark -q -r ${1} -z "io,stat,${3},$(tshark -t e -r ${1} -R "wlan.fcs_good==1 and wlan.fc.type_subtype==0x08 and wlan_mgt.tag.interpretation==\"${2}\"" -T fields -e wlan.sa | sort | uniq | awk '{printf("%swlan&&(wlan.ta==%s||wlan.sa==%s||wlan.bssid==%s||wlan.ra==%s)",sep,$1,$1,$1,$1);sep=","}')"

