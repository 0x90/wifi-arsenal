#!/bin/bash

./beacons -i $1 | sed 's/^/(/' | sed 's/$/)/' | ./zeroise.scm | sed 's/^(//' | sed 's/)$//' | awk '{ print $1, $2, $3, $3-341; }' | awk 'BEGIN { t=0; x=0; }
{ if(int($2/1e6) > t) { print t, x; t=int($2/1e6); x=$4; } else { x+=$4; }}' 

exit 0