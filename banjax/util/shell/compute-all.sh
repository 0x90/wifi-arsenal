#!/bin/bash

cd ~/SourceCode/ELC/src
export RUNTIME=15
export MPDU=1090
export TA=00:0b:6b:0a:82:34

p=$1
r=`basename "$p"`
r="${p/test\//results/}"

# compute dead time
(cd beacons/; ./compute-dead.sh "$p/38")

# compute actual contention distribution
(cd contention/; ./compute.sh "$p/38")

# compute theoretical contention distribution
(cd txc/; ./compute.sh "$p/28")

# process individual pcaps
(cd elc; ./compute.sh "$p/28")

# process summary of individual experiments
(cd elc; ./summarize.sh $p/28 > "$r/summary.dat")
