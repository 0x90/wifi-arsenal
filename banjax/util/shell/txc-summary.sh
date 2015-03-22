#!/bin/bash

p="$1"
[ "$RUNTIME" != "" ] && RUNTIME="--runtime $RUNTIME"

if [ ! -d $p ]; then
	 echo "error:  bad path to pcap directory" 2>&1
	 exit 1
fi

echo "# TXC summary"
echo "# Source: $p"
echo

for r in 6 9 12 18 24 36 48 54; do
	 files="${p}/*load${r}*.pcap"
	 for f in $files; do 
		  if [ -s "$f" ]; then
				a=${f/*att/}
				a=${a/_load*/}
				s=`./elc --input $f $RUNTIME --linkrate $r | awk -f plot.awk`
				if [ "$s" != "" ]; then 
					 echo -n "$r $a "
					 echo $s | ./extract.scm TXC
				else
					 echo "$r $a -"
				fi
		  fi
	 done
	 echo
	 echo
done


