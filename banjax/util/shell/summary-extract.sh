#!/bin/bash

case "$#" in
	 0) 
		  echo "usage: summary-compare path field field*" 2>&1
		  exit 1
		  ;;
	 *)
		  p="$1"
		  shift
		  ;;
esac

if [ ! -d "$p" ]; then
	 echo "$p is not a directory!" 2>&1
	 exit 2
fi

echo "# Source: $p"
echo "# Fields: $*"
echo "#"

(for f in $p/*.data; do echo -n "$f "; ./extract.scm $* < $f | awk '{ print $1 * 8, $2 * 8; }'; done) | sed 's/.*att//' | sed 's/\.00.*data//' | sed 's/_load/ /' | awk '{ print $2, $1, $3; }' | sort -k1n -k2n | awk -f block.awk | awk -f block.awk

