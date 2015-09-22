#!/bin/sh
#merge all the histograms into one histogramm for better R plotting

for file in $(ls -v *24h-histogram*); 
do
	nodename="$(echo $file | cut -d'-' -f 1)"
	
	if [ ! -f "all-node-histogram.csv" ]; then
		echo "node noise count" > all-node-histogram.csv
	fi

	cat $file | awk -F',' '{print "'"$nodename"'",$1,$2}' >> all-node-histogram.csv


done
