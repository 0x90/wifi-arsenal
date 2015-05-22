#!/usr/bin/gnuplot

set term postscript color enhanced eps
set out "plot.eps"

# function to convert MiB/s -> Mb/s
Mb(x)=(x * 8)

set ytics nomirror
set y2tics
set xlabel "Time (s)"
set ylabel "Data (Mb/S)"
set y2label "#"

plot "plot.data" using 1:(Mb($2)) with lines title "Goodput", \
	  "plot.data" using 1:(Mb($4)) with lines title "Residual(Goodput)", \
	  "plot.data" using 1:(Mb($5)) with lines title "ELC", \
	  "plot.data" using 1:(Mb($6)) with lines title "ELC-MRR", \
	  "plot.data" using 1:(Mb($7)) with lines title "ELC-Legacy", \
	  "plot.data" using 1:(Mb($8)) with lines title "ELC-Classic", \
	  "plot.data" using 1:(Mb($9)) with lines title "Residual(ELC-Legacy)", \
	  "plot.data" using 1:10 with lines title "packets" axes x1y2, \
	  "plot.data" using 1:11 with lines title "frames" axes x1y2, \
	  "plot.data" using 1:12 with lines title "TXC" axes x1y2



