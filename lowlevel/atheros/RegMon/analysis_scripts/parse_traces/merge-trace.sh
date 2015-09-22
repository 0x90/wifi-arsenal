#!/bin/sh
# This tool takes thomas traces and merge them to one file


for FILE in `ls -v *.trace`; do
	NODE=`echo $FILE|awk -F'.' '{print $1}'|awk -F'-' '{print $1}'`
	RATE=`echo $FILE|awk -F'.' '{print $1}'|awk -F'-' '{print $2}'` 
	POWER=`echo $FILE|awk -F'.' '{print $1}'|awk -F'-' '{print $3}'`  
	if [ ! -f "$NODE.mtrace" ]; then
		echo "rate power noise" > $NODE.mtrace
	fi

	#print only the noisefloor calculated from the register value
	#define AR_PHY_CCA              0x9864 
	#define AR_PHY_MINCCA_PWR       0x0FF80000 
	#define AR_PHY_MINCCA_PWR_S     19 

	cat $FILE|awk  '{ print "'"$RATE"'" " " "'"$POWER"'" " " xor(rshift(strtonum($6),19), 0x1ff) }' >> $NODE.mtrace
done
