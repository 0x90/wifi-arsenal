#!/bin/bash
#limit the number of jobs to be processed

maxjobs="5"
jobsrunning="0"

for node in a af tel c ma tc bib vws sg en ew eb hft
do
    for time in 1 10 60 600 3600
    do
     if [ $jobsrunning -le $maxjobs ]
        then 
            nice -19 ./one-column-stats-v2.py -d ',' -D ',' -H -c 6 -w "$time" -o aggregation/${node}-${time}-sec ${node}-24h-register.csv &
            echo $node
            jobsrunning="$((jobsrunning+1))"
        else 
    	wait
	    jobsrunning="0"
     fi
    done
done


