#!/bin/bash

n=$1
shift
for p in $*; do

	d="txc-$n.$$"
	e="txc-$n.eps"
	./analyse -i "$p" 2> /dev/null | awk "{ if(\$4 == $n) print \$3; }" | sort -n | uniq -c > "$d"

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

	rm -f "$d"

done

exit 0
