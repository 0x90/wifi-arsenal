#!/bin/bash

h=`dirname $0`

if [ $# -lt 3 ]; then
	 echo "usage: plot-some.sh file.data field [field*]"	1>&2
	 exit 1
fi

d="$1"
shift 1
fields="$*"

o="${d/.data/.eps}"
t="${d/.data/.extract}"

declare -A axis
axis["Octets"]="axes x1y2"
axis["Packets"]="axes x1y2"
axis["Frames"]="axes x1y2"
axis["TXC"]="axes x1y2"
axis["FDR"]="axes x1y2"

# write the extract file
OPTS=""
if [ ! -e "$d" ]; then
	 echo 1>&2 "error: $d is missing!"
	 exit 1
fi

# extract data to plot
$h/extract.scm Time $fields < "$d" > "$t"

# direct to gnuplot unless told otherwise
[ "$OUT" == "" ] && OUT=`which gnuplot`

# prepare the plot string
if [ -s "$t" ]; then
	 s=""
	 d=""
	 axis2=""
	 let n=2
	 for f in $*; do
		  if [[ "${f/-*/}" == "Airtime" && "$f" != "Airtime-NS3" ]]; then
				s="${s}${d}\"${t}\" using 1:(rate(\$${n})) with lp title \"${f}\""
		  elif [ "${axis[$f]}" == "" ]; then
				s="${s}${d}\"${t}\" using 1:(Mb(\$${n})) with lp title \"${f}\""
		  else
				s="${s}${d}\"${t}\" using 1:${n} with lp title \"${f}\" ${axis[$f]}"
				axis2='set y2label "Count"'
				# Add this? set y2tics
		  fi
		  d=", "
		  let n=n+1
	 done
	 [ "$XRANGE" != "" ] && XRANGE="set xrange [$XRANGE]"
	 [ "$YRANGE" != "" ] && YRANGE="set yrange [$YRANGE]"
	 [ "$Y2RANGE" != "" ] && Y2RANGE="set y2range [$Y2RANGE]"
	 ${OUT} <<EOF
set term postscript enhanced eps
set out "$o"

# function to convert MB/s -> Mb/s
Mb(x)=x*8

# function to convert airtime to data rate
rate(x)=8192.0/x

set key below
set grid xtics ytics
set ytics nomirror

set xlabel "Time (s)"
set ylabel "Traffic (Mb)"
$axis2

$XRANGE
$YRANGE
$Y2RANGE

plot $s 
EOF
	 # if [ -f "${t}" ]; then
	 # 	  rm "$t"
	 # fi

	 if [[ -f "${o}" && ! -s "${o}" ]]; then
		  rm "$o"
	 fi
else
	 echo "warning: extract failed for ${p}" 2>&1
	 exit 1
fi

exit 0
