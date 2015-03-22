#!/bin/bash

if [ $# != 1 ]; then
	 echo "usage: $0 path-to-pcaps" 1>&2
	 exit 1
fi


p="$1"
if [ ! -d $p ]; then
	 echo "error: bad path to pcap directory" 1>&2
	 exit 1
fi

if [ "$RUNTIME" == "" ]; then
	 echo No RUNTIME specified - assuming 15s! 2>&1
	 export RUNTIME=15
fi

OPTS=""
[ "$CW" != "" ] && OPTS+="--cw $CW "
[ "$MPDU" != "" ] && OPTS+="--mpdu ${MPDU} "
[ "$RUNTIME" != "" ] && OPTS+="--runtime ${RUNTIME} "

echo "# Source: $p"
echo "# Generator: $0 $*"
echo
for r in 6 9 12 18 24 36 48 54; do
	 files="${p}/*load${r}*.pcap"
	 for f in $files; do 
		  if [ -s "$f" ]; then
				t="${f/test\//results/}"
				d="${t/28/38}"
				d="${d/.pcap/.dead}.${RUNTIME}"
				if [ -s "$d" ]; then
					 x=`cat "$d"`
					 [ "$x" != "\
" ] && x="--dead $x"
				else
					 echo "warning: no dead time for ${f}!" 2>&1
				fi
				a=${f/*att/}
				a=${a/_load*/}
				s=`./elc --input $f $OPTS --linkrate $r $x | awk -f plot.awk`
				if [ "$s" != "" ]; then 
					 echo "Rate: $r, Att: $a, $s"
				fi
		  fi
	 done
	 echo
	 echo
done
