#!/bin/sh
# This tool takes thomas traces and merge them to one file

for node in tel a af ma tc eb en ew sg c bib vws hft 
do
	for FILE in $(ls -v $node-sender=vws*register.csv); do

		NODE=`echo $FILE|awk -F'-' '{print $1}'`
		SENDER=`echo $FILE|awk -F'-' '{print $2}'` 
		
		CH=`echo $FILE|awk -F'-' '{print $3}'|awk -F'=' '{print $2}'`
		CALI=`echo $FILE|awk -F'-' '{print $4}'|awk -F'=' '{print $2}'`
		PSIZE=`echo $FILE|awk -F'-' '{print $5}'|awk -F'=' '{print $2}'|tr -d "B"`
		OFDM=`echo $FILE|awk -F'-' '{print $6}'|awk -F'=' '{print $2}'`
		CCA=`echo $FILE|awk -F'-' '{print $7}'|awk -F'=' '{print $2}'`
		NOISE=`echo $FILE|awk -F'-' '{print $8}'|awk -F'=' '{print $2}'`
		MODULATION=`echo $FILE|awk -F'-' '{print $9}'|awk -F'=' '{print $2}'`
		TXPOWER=`echo $FILE|awk -F'-' '{print $10}'|awk -F'=' '{print $2}'`

		
		if [ ! -f "$NODE-$SENDER-register.csv" ]; then
			echo "channel calibration packetsize ofdm cca noise modulation txpower timestamp mac_counter_diff tx_counter_diff rx_counter_diff ed_counter_diff noise rssi nav tsf_upper tsf_lower phy_errors potential_reset expected_mac_count" > $NODE-$SENDER-register.csv
		fi
		
		tail -n +2 $FILE | awk -F',' '{ print "'"$CH"'","'"$CALI"'","'"$PSIZE"'","'"$OFDM"'","'"$CCA"'","'"$NOISE"'","'"$MODULATION"'","'"$TXPOWER"'",$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13}' >>  $NODE-$SENDER-register.csv
	done
	
	for FILE in $(ls -v $node-sender=ma*register.csv); do

		NODE=`echo $FILE|awk -F'-' '{print $1}'`
		SENDER=`echo $FILE|awk -F'-' '{print $2}'` 
		
		CH=`echo $FILE|awk -F'-' '{print $3}'|awk -F'=' '{print $2}'`
		CALI=`echo $FILE|awk -F'-' '{print $4}'|awk -F'=' '{print $2}'`
		PSIZE=`echo $FILE|awk -F'-' '{print $5}'|awk -F'=' '{print $2}'|tr -d "B"`
		OFDM=`echo $FILE|awk -F'-' '{print $6}'|awk -F'=' '{print $2}'`
		CCA=`echo $FILE|awk -F'-' '{print $7}'|awk -F'=' '{print $2}'`
		NOISE=`echo $FILE|awk -F'-' '{print $8}'|awk -F'=' '{print $2}'`
		MODULATION=`echo $FILE|awk -F'-' '{print $9}'|awk -F'=' '{print $2}'`
		TXPOWER=`echo $FILE|awk -F'-' '{print $10}'|awk -F'=' '{print $2}'`

		
		if [ ! -f "$NODE-$SENDER-register.csv" ]; then
			echo "channel calibration packetsize ofdm cca noise modulation txpower timestamp mac_counter_diff tx_counter_diff rx_counter_diff ed_counter_diff noise rssi nav tsf_upper tsf_lower phy_errors potential_reset expected_mac_count" > $NODE-$SENDER-register.csv
		fi
		
		tail -n +2 $FILE | awk -F',' '{ print "'"$CH"'","'"$CALI"'","'"$PSIZE"'","'"$OFDM"'","'"$CCA"'","'"$NOISE"'","'"$MODULATION"'","'"$TXPOWER"'",$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13}' >>  $NODE-$SENDER-register.csv
	done
	
	for FILE in $(ls -v $node-sender=tel*register.csv); do

		NODE=`echo $FILE|awk -F'-' '{print $1}'`
		SENDER=`echo $FILE|awk -F'-' '{print $2}'` 
		
		CH=`echo $FILE|awk -F'-' '{print $3}'|awk -F'=' '{print $2}'`
		CALI=`echo $FILE|awk -F'-' '{print $4}'|awk -F'=' '{print $2}'`
		PSIZE=`echo $FILE|awk -F'-' '{print $5}'|awk -F'=' '{print $2}'|tr -d "B"`
		OFDM=`echo $FILE|awk -F'-' '{print $6}'|awk -F'=' '{print $2}'`
		CCA=`echo $FILE|awk -F'-' '{print $7}'|awk -F'=' '{print $2}'`
		NOISE=`echo $FILE|awk -F'-' '{print $8}'|awk -F'=' '{print $2}'`
		MODULATION=`echo $FILE|awk -F'-' '{print $9}'|awk -F'=' '{print $2}'`
		TXPOWER=`echo $FILE|awk -F'-' '{print $10}'|awk -F'=' '{print $2}'`

		
		if [ ! -f "$NODE-$SENDER-register.csv" ]; then
			echo "channel calibration packetsize ofdm cca noise modulation txpower timestamp mac_counter_diff tx_counter_diff rx_counter_diff ed_counter_diff noise rssi nav tsf_upper tsf_lower phy_errors potential_reset expected_mac_count" > $NODE-$SENDER-register.csv
		fi
		
		tail -n +2 $FILE | awk -F',' '{ print "'"$CH"'","'"$CALI"'","'"$PSIZE"'","'"$OFDM"'","'"$CCA"'","'"$NOISE"'","'"$MODULATION"'","'"$TXPOWER"'",$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13}' >>  $NODE-$SENDER-register.csv
	done
	
done




#		NODE=`echo $FILE|awk -F'.' '{print $1}'|awk -F'-' '{print $1}'`
