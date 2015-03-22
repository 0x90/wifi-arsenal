#!/bin/bash

D=$1
./extract.scm Frames-Attempted Packets < $D | awk 'BEGIN { x1=0; x2=0; }
{ x1+=$1; x2+=$2; }
END { if((NR > 0) && x2 > 0) { print x1/x2; } else { print "-"; } }'
exit 0
