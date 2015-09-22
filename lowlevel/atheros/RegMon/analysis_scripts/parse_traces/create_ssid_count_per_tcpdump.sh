#!/bin/bash
# this script parse all *.cap 802.11 traces within the current folder and search all uniq SSIDs from beacons -> into a txt file into $OUT

CLICK_PARSER=/data/nfs/thomas/experiments/scripts/parser-scripts/exctract-SSID.click
EXPDIR=$(pwd)
OUT=$1

maxjobs="2"
jobsrunning="0"

for CAP in $(ls -v *mon1*pcap)
do
	nodename=$(echo $CAP | cut -d'.' -f1)
	if [ $jobsrunning -le $maxjobs ]
	then 
    	echo "parsing $CAP"
        (time nice -19 click $CLICK_PARSER TRACE=$CAP 2>&1 | cut -d'|' -f 3 | cut -d' ' -f 5 | sort | uniq > ${OUT}/${nodename}-all-ssids.txt) &
        jobsrunning="$((jobsrunning+1))"
	else
    	echo "parsing $CAP"
        (time nice -19 click $CLICK_PARSER TRACE=$CAP 2>&1 | cut -d'|' -f 3 | cut -d' ' -f 5 | sort | uniq > ${OUT}/${nodename}-all-ssids.txt) &
    	wait
	    jobsrunning="0"
    fi
done

echo "all ssid parsing finished"
