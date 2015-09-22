#!/bin/sh
#
# Start multiple trace scripts to collect measurements
#

export PATH=/bin:/sbin:/usr/bin:/usr/sbin

DEST=/tmp/traces
HOSTNAME=$(cat /proc/sys/kernel/hostname | cut -d'-' -f1)

PID_PCAP=/var/run/tcpdump_0.pid
PID_RCSTATS=/var/run/rc_stats_trace.pid
PID_CPUSAGE=/var/run/cpusage.pid

save_config() {
	/sbin/uci show > ${DEST}/${TITLE}-uci.conf
	/sbin/sysctl -A 2>/dev/null > ${DEST}/${TITLE}-sysctl.conf
	/bin/date > ${DEST}/${TITLE}-date.conf
	#tar -cvf ${DEST}/${TITLE}-node_configuration.tar ${DEST}/${TITLE}*.conf &> /dev/null
	#rm -rf ${DEST}/${TITLE}*.conf
}

clear() {
	echo "deleting traces in '${DEST}'"
	rm ${DEST}/* 2>/dev/null
}

rc_stats_tracing() {
	if [ ! -f $PID_RCSTATS ] && $(ifconfig mon0 &> /dev/null); then
		OUTFILE="${DEST}/${TITLE}-rc_stats.log"
		rm $OUTFILE 2>/dev/null
		(while [ 1 ]; do
			for sta in `ls /sys/kernel/debug/ieee80211/phy0/netdev\:wlan0/stations/`; do
				cat /sys/kernel/debug/ieee80211/phy0/netdev\:wlan0/stations/$sta/*stats_csv | sed 's/^/'$sta',/' - >> $OUTFILE
			done
			usleep 50000
		done ) &
		PID=$!
		echo $PID > $PID_RCSTATS
	fi
}

pcap_tracing() {
	if [ ! -f $PID_PCAP ] && $(ifconfig mon0 &> /dev/null); then
		(/usr/sbin/tcpdump -i mon0 -s 150 -U -w - 2> /dev/null | lzop -1 > ${DEST}/${TITLE}-mon0.pcap.lzop) &
		PID=$!
		echo $PID > $PID_PCAP
	fi
}

cpusage_tracing() {
	if [ ! -f $PID_CPUSAGE ]; then
		CPUFILE="${DEST}/${TITLE}-cpusage.log"
		( /usr/bin/cpusage > "$CPUFILE" ) &
		PID=$!
		echo $PID > $PID_CPUSAGE
	fi
}

#start all trace functions
start() {
	echo -n "starting traces for $TITLE... "
	save_config $TITLE
	#echo "starting pcap tracing"
	pcap_tracing $TITLE
	#echo "starting rc_stats tracing"
	rc_stats_tracing $TITLE
	#echo "starting cpusage tracing"
	cpusage_tracing $TITLE
	echo "done"
}

stop() {

	echo -n "stopping traces for $TITLE... "
	#echo "stopping pcap tracing"
	[ -f "$PID_PCAP" ] && kill $(cat $PID_PCAP) 2> /dev/null 1>/dev/null
	rm $PID_PCAP 2>/dev/null
	#echo "stopping rc_statss tracing"
	[ -f "$PID_RCSTATS" ] && kill $(cat $PID_RCSTATS) 2>/dev/null 1>/dev/null
	rm $PID_RCSTATS 2>/dev/null
	#echo "stopping cpusage tracing"
	[ -f "$PID_CPUSAGE" ] && kill $(cat $PID_CPUSAGE) 2>/dev/null 1>/dev/null
	rm $PID_CPUSAGE 2>/dev/null
	killall tcpdump lzop 2>/dev/null
	echo "done"
}

case "$1" in
	start)
		TITLE=${2:-test-run}
		mkdir "$DEST" 2>/dev/null
		start $TITLE
	;;
	stop)
		stop
	;;
	clear)
		clear
	;;
	restart)
		stop
		start
	;;
	*)
		echo "Usage: $0 {start|stop|restarti <title>}"
esac
