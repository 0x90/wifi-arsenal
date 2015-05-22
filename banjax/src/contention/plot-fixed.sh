#!/bin/bash

[ "$LIMIT" = "" ] && LIMIT=2000

for p in $*; do

	c="${p/.pcap/.cw}"
	d="${p/.pcap/.data}"
	e="${p/.pcap/.fixed.eps}"
	./analyse -i "$p" 2> "$c" | awk '{ print $3; }' | sort -n | uniq -c | awk '{ print $2, $1; }' > "$d"

	gnuplot <<EOF
#!/usr/bin/gnuplot

set term postscript color enhanced eps
set out "$e"

set style fill solid
set style histogram
set style data histograms

set xlabel "delay (us)"
set ylabel "frequency"
set xrange [:$LIMIT]

plot "$d" using 1:2 with boxes title "frequency"

EOF

done
