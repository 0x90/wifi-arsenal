#!/bin/bash

case "$#" in
	 1)
		  p="$1"
		  w="TXC"
		  fn="avg"
		  un=""
		  ;;
	 2)
		  p="$1"
		  w="$2"
		  fn="avg"
		  un=""
		  ;;
	 2)
		  p="$1"
		  w="$2"
		  fn="$3"
		  un=""
		  ;;
	 2)
		  p="$1"
		  w="$2"
		  fn="$3"
		  un="$4"
		  ;;
	 *)
		  echo "usage: summary.sh path what fn [Mb]" 2>&1
		  exit 1
		  ;;
esac

if [ ! -d "$p" ]; then
	 echo "$p is not a directory!" 2>&1
	 exit 2
fi


echo "# Source: $p"
echo "# Generator: $0 $*"
echo "#"

for r in 6 9 12 18 24 36 48 54; do
	files="${p}/*load${r}*.data"
	for f in $files; do
		a=`echo $f | sed 's/.*att//' | sed 's/_load.*//'`;
		echo -n "$r $a ";
		if [ "$un" == "Mb" ]; then
			 ./extract.scm "$w" < "$f" | awk -f Mb.awk | awk -f "${fn}.awk"
		else
			 ./extract.scm "$w" < "$f" | awk -f "${fn}.awk"
		fi
	done
done

exit 0
