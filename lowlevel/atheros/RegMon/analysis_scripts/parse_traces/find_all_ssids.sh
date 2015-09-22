#!/bin/sh
#
# prints all un-hidden ssids within a pcap file on $1 and the uniq accesspoints  
# Thomas Huehn, April 2011

#limit the number of parallel jobs
maxjobs="1"
jobsrunning="0"

FILTER_BSSID="wlan.fcs_good==1 and wlan.fc.type_subtype==0x08 and wlan_mgt.tag.interpretation==\"${ssid}\""
FILTER_SSID="wlan.fc.type_subtype==0x08 && radiotap.flags.badfcs == 0"

_FIND_SSID () {
	nice -19 tshark -r $1 "$FILTER_SSID" -T fields -e "wlan_mgt.tag.interpretation" 2> /dev/null | cut -d',' -f 1 | sed 's/^Supported rates: .*$//' | sort | uniq
}

#use new line for IFS becasue SSID can have weird characters
IFS='
'

for ssid in $(_FIND_SSID $1); do 
	if [ $jobsrunning -le $maxjobs ]
	then
		(
			ap="$(nice -19 tshark -t e -r $1 -R "$FILTER_BSSID" -T fields -e "wlan.sa" 2> /dev/null | sort | uniq | wc -l)"
			echo "$ssid $ap" 
		) &
		jobsrunning="$((jobsrunning+1))"
	else
		wait
		jobsrunning="0"
	fi
done

unset IFS

