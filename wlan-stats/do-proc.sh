#!/bin/sh
#Hugh O'Brien 2014, obrien.hugh@gmail.com
#if tshark is slow, but doesn't seem to be cpu or mem bound, check to see if it's trying to do dns lookups

[ -z "$1" ] && echo "specify input file" && exit

post_proc='proc.py'
[ ! -f "$post_proc" ] && echo "$post_proc not found" && exit

base="$(basename "$1")"
outfile="$base.csv.xz"
errfile="$base.csv.err"

tshark -r "$1" -T fields -E separator=',' -e frame.number -e radiotap.length -e radiotap.mactime -e radiotap.flags.preamble -e radiotap.datarate -e frame.len -e radiotap.dbm_antsignal | python "$post_proc" 2>"$errfile" | xz -9 --extreme --verbose > "$outfile"

cat "$errfile"
