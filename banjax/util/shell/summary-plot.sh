#!/bin/bash

case "$#" in
	 1)
		  p="$1"
		  m="Goodput"
		  ;;
	 2)
		  p="$1"
		  m="$2"
		  ;;
	 *)
		  echo "usage: summary-plot path [metric]" 2>&1
		  exit 1
		  ;;
esac

if [ ! -d "$p" ]; then
	 echo "$p is not a directory!" 2>&1
	 exit 2
fi


echo "# Source: $p"
echo "# Metric: $m"
echo "#"

(for f in $p/*.data; do echo -n "$f "; ./extract.scm "${m}" < $f | awk '{ print $1 * 8, $2 * 8; }' | awk -f "${fn}.awk"; done) | sed 's/.*att//' | sed 's/\.00.*data//' | sed 's/_load/ /' | awk '{ print $2, $1, $3; }' | sort -k1n -k2n  | awk  -f block.awk

