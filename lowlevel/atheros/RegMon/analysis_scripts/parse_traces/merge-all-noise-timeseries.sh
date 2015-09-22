#!/bin/sh
#merge 1sec noise timeseries of all nodes into one single file 

TARGET=all-nodes-1sec-noise-timeserie.csv


for file in $(ls -v *-1-sec-aggregation.csv*); 
do
	nodename="$(echo $file | cut -d'-' -f 1)"
	
	if [ ! -f $TARGET ]; then
		echo "node timestamp mean median max min std" > $TARGET
	else echo "file und header angelegt .. daten kommen"
	fi

	tail -n +2 $file | awk -F',' '{print "'"$nodename"'",$1,$2,$3,$4,$5,$6,$7}' >> $TARGET
	echo "FILE $file done"
done
