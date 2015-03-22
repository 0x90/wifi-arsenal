#!/bin/bash

if [ $# != 1 ]; then
	 echo "usage: $0 path-to-distribs" 1>&2
	 exit 1
fi

p="$1"
if [ ! -d $p ]; then
	 echo "error: bad path to results directory" 1>&2
	 exit 1
fi

for r in 6 9 12 18 24 36 48 54; do
	 files="${p}/*load${r}*.distrib"
	 for f in $files; do
		  e="${f/.distrib/.eps}"
		  c="${f/28/38}"
		  c="${c/.distrib/.data}"
		  if [[ -s "$f" && -s "$c" ]]; then
				gnuplot <<EOF
#!/usr/bin/gnuplot

set term postscript enhanced eps
set out "$e"

set key below

set xlabel "Slot"
set ylabel "Count"

set xrange [0:256]
set style fill solid
set style histogram
set style data histograms

plot "$f" using 1:2 with lines title "theoretic", \
     "$c" using 2:1 with impulses title "actual"

EOF
		  fi
	 done
done
exit 0
