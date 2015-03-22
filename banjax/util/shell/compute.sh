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

o="${p/test\//results/}"
[ ! -d "$o" ] && mkdir -p "$o"

OPTS=""
[ "$CW" != "" ] && OPTS+="--cw ${CW} "
[ "$RUNTIME" != "" ] && OPTS+="--runtime ${RUNTIME} "
[ "$ACKTIMEOUT" != "" ] && OPTS+="--acktimeout ${ACKTIMEOUT} "

for r in 6 9 12 18 24 36 48 54; do
	files="${p}/*load${r}*.pcap"
	for f in $files; do
		t="${f/test\//results/}"
		t="${t/.pcap/.data}"
		./elc --ticks --linkrate $r --input "$f" --runtime 20 | sed 's/nan/0/g' > "$t"
	done
done

exit 0
