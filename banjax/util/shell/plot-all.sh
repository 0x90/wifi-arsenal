#!/bin/sh

P=$1
for R in 6 9 12 18 24 36 48 54; do
	 YRANGE="0:${R}" RATE=$R ./plot.sh $P/*load${R}*.data
done
exit 0
