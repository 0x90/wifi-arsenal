#!/bin/bash

[ "$TA" != "" ] && TA="--ta ${TA}"

for p in $*; do

	 o="${p/test/results}"
	 if [ -d "$p" ]; then
		  odir="$o"
	 else
		  odir=`dirname "$o"`
	 fi
	 [ ! -d "$odir" ] && mkdir -p "$odir"

	 c="${o/.pcap/.cw}"
	 d="${o/.pcap/.data}"
	 e="${o/.pcap/.eps}"

	 ./analyse ${TA} -i "$p" 2> "$c" | awk '{ print $3; }' | sort -n | uniq -c > "$d"

	 gnuplot <<EOF
#!/usr/bin/gnuplot

set term postscript color enhanced eps
set out "$e"

set style fill solid
set style histogram
set style data histograms

set xlabel "delay (us)"
set ylabel "frequency"

plot "$d" using 2:1 with boxes title "frequency"

EOF

done
exit 0
