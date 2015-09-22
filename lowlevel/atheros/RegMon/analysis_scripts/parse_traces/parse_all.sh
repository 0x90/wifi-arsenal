#!/bin/bash
#
# parse trace files with our tools
#

#static variables
EXPDIR=$(pwd)
NODELIST=$EXPDIR/asus-node-list.txt
TCP_PARSER=/data/nfs/thomas/experiments/scripts/parser-scripts/parse_tcpdump.sh
STATS_PARSER=/data/nfs/thomas/experiments/scripts/parser-scripts/parse_xstats_v2.pl
REG_PARSER=/data/nfs/thomas/experiments/scripts/parser-scripts/parse_register_reloaded.pl
AWK_THR=/data/nfs/thomas/experiments/scripts/parser-scripts/awk-extract-thr.awk

REG_OPTIONS='timestamp 0 0 mac_counter_diff 1 0 tx_counter_diff 1 0 rx_counter_diff 1 0 ed_counter_diff 1 0 noise 0 1 rssi 0 0 nav 0 0 tsf_upper 0 0 tsf_lower 0 0 phy_errors 0 0'

MAC_HZ=40	#channel 165
#limit the number of jobs to be processed
maxjobs="2"
jobsrunning="0"

echo "*** parsing traces started ***"

#create directories
test ! -d "$EXPDIR/data/datamining" && mkdir -p $EXPDIR/data/datamining
IN="$EXPDIR/data/traces"
OUT="$EXPDIR/data/datamining"

cd $IN

# parse all register files 
for FILE in *lzop
do
	nodename="$(echo $FILE | cut -d'.' -f1)"
	if [ $jobsrunning -le $maxjobs ]
	then
	    echo "node $nodename"
	    (nice -19 lzop -fcd $FILE 2> /dev/null | $REG_PARSER -c "$REG_OPTIONS" -m $MAC_HZ  > $OUT/$nodename.csv) &
	    jobsrunning="$((jobsrunning+1))"
	else
	    echo "node $nodename"
	    (nice -19 lzop -fcd $FILE 2> /dev/null | $REG_PARSER -c "$REG_OPTIONS" -m $MAC_HZ  > $OUT/$nodename.csv) &
	    wait
	    jobsrunning="0"
	fi
done

#parse iperf logs
#echo "sensivity rate power iperf_thr iperf_jitter" > $OUT/iperf-summary-hft-2-en.csv
#
#for FILE in $(ls -v *iperf*)
#do
#	sens="$(echo $FILE | cut -d'=' -f2 | cut -d'_' -f1)"
#	tx="$(echo $FILE | cut -d'=' -f4 | cut -d'.' -f1)"
#	RATE="$(echo $FILE | cut -d'=' -f3 | cut -d'_' -f1)"
#	cat $FILE | awk  -v SENS=$sens -v MOD=$RATE -v TX=$tx -f $AWK_THR | \
#	(echo "sensivity rate power iperf_thr iperf_jitter"; cat -) \
# 	>> $OUT/iperf-summary-hft-2-en.csv
#done

# parse pcap files
# bad fcs packets are not passed to the ath5k mac
# iperf with discrete packet length
TSHARK=/usr/local/bin/tshark

VWS_IP='10.10.18.10'
VWS_MAC='00:0b:6b:2c:ee:ca'
H_IP='10.10.15.18'
H_MAC='00:0b:6b:2c:ee:ba'
TC_IP='10.10.9.10'
TC_MAC='00:0b:6b:20:dd:44'
EN_IP='10.10.10.18'
EN_MAC='00:0b:6b:2c:fc:5c'

RECEIVER=$VWS_MAC

#create files with headers
#for node in $(cat $NODELIST)
#do
#	nodename=en-v1
#done

for FILE in *.pcap
do
	nodename='vws'
	version="$(echo $FILE | cut -d'-' -f4 | cut -d'.' -f1)"
#	sens="$(echo $FILE | cut -d'=' -f2 | cut -d'_' -f1)"
#	tx="$(echo $FILE | cut -d'=' -f4 | cut -d'.' -f1)"
#	RATE="$(echo $FILE | cut -d'=' -f3 | cut -d'_' -f1)"

	echo "snr counts" > $OUT/"$nodename"-udp-data-snr-histogram-"$version".csv
    echo "snr counts" > $OUT/"$nodename"-ack-snr-histogram-"$version".csv
    echo "pkt_len counts" > $OUT/"$nodename"-all-frame_len-histogram-"$version".csv
    echo "time mac.time seq.nr snr pkt.len retry.bit datarate" > $OUT/"$nodename"-snr-timeserie-"$version".csv
    echo "timeslot frame.count byte.rate bit.rate" > $OUT/"$nodename"-throughput-timeserie-"$version".csv
	#tshark filters
	FILTER_ACK="wlan.fc.type_subtype==0x1d"
	FILTER_GOODPUT="wlan.fc.type==2&&wlan.da=="$RECEIVER""
	FILTER_BADPUT="wlan.da!="$RECEIVER""

	#create histograms
(	$TSHARK -r $FILE -R $FILTER_GOODPUT \
		-T fields -e radiotap.dbm_antsignal 2> /dev/zero | \
		awk ' NF > 0{ counts[$0] = counts[$0] + 1; } END { for (word in counts) print word, counts[word]; }' \
		>> $OUT/"$nodename"-udp-data-snr-histogram-"$version".csv ) &

(	$TSHARK -r $FILE -R $FILTER_ACK \
		-T fields -e radiotap.dbm_antsignal 2> /dev/zero | \
		awk ' NF > 0{ counts[$0] = counts[$0] + 1; } END { for (word in counts) print word, counts[word]; }' \
		>> $OUT/"$nodename"-ack-snr-histogram-"$version".csv ) &

(	$TSHARK -r $FILE "-T fields -e frame.len" 2> /dev/zero | \
		awk ' NF > 0{ counts[$0] = counts[$0] + 1; } END { for (word in counts) print word, counts[word]; }' \
		>> $OUT/"$nodename"-all-frame_len-histogram-"$version".csv ) &

	#create SNR timeseries of udp packets
(	$TSHARK -r $FILE -R $FILTER_GOODPUT \
		-T fields -e frame.time_relative -e radiotap.mactime -e wlan.seq -e radiotap.dbm_antsignal -e frame.len -e wlan.fc.retry -e radiotap.datarate | \
		awk '{print $1, $2, $3, $4, $5, $6, $7}' \
		>> $OUT/"$nodename"-snr-timeserie-"$version".csv ) &

	#create throughput timeseries graphs
(	$TSHARK -r $FILE -R $FILTER_GOODPUT -w - | tcpstat -r - -o "%R %n %N %b \n" 1 | \
		awk '{print $1, $2, $3, $4}' \
		>> $OUT/"$nodename"-throughput-timeserie-"$version".csv ) &
	wait
done





#athstats trace
#for FILE in $(ls -v *athtrace*)
#do
#	if [ $jobsrunning -le $maxjobs ]
#	then
#    	nodename="$(echo $FILE | cut -d'.' -f1)"
#	    (nice -19 lzop -fd $FILE; nice -19 $STATS_PARSER $nodename $OUT; rm $nodename) &
#	else
#	    wait
#	    jobsrunning="0"
#	fi
#done

cd $EXPDIR
sleep 2

echo "... ALL DONE"

     #TODO: alle Traces einpacken um Platz zu sparen

