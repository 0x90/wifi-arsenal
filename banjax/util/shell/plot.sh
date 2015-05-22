#!/bin/bash

h=`dirname $0`
for f in $*; do
	 $h/plot-some.sh "${f}" TMT Goodput Airtime-Measured Airtime-Measured-5PC Airtime-Measured-10PC Airtime-Measured-25PC Airtime-Kernel Airtime-NS3
done

exit 0
