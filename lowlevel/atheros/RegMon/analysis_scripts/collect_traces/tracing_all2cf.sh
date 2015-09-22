#!/bin/sh
##
### Start multiple trace scripts to collect measurements
##

export PATH=/bin:/sbin:/usr/bin:/usr/sbin

#dest of cf card hardcoded
DEST=/data/traces
HOSTNAME=$(cat /proc/sys/kernel/hostname | cut -d'-' -f1)

Save_config() {
	/sbin/uci show > ${DEST}/${TITLE}-uci.conf
	/sbin/sysctl -A 2>&1 > ${DEST}/${TITLE}-sysctl.conf
	/bin/date > ${DEST}/${TITLE}-date.conf
	[ -f /sys/kernel/debug/ieee80211/phy0/ath5k/ani ] && cat /sys/kernel/debug/ieee80211/phy0/ath5k/ani > ${DEST}/${TITLE}-ani.conf
	tar -cvf ${DEST}/${TITLE}-node_configuration.tar ${DEST}/${TITLE}*.conf &> /dev/null
	rm -rf ${DEST}/${TITLE}*.conf
}


Pcap_tracing() {
	PID_0=/var/run/tcpdump_0.pid
	PID_1=/var/run/tcpdump_1.pid
	if [ ! -f $PID_0 ] && $(ifconfig mon0 &> /dev/null); then
		(tcpdump -i mon0 -s 150 -U -w - 2> /dev/null | lzop -1 > ${DEST}/${TITLE}-mon0.pcap.lzop) &
		PID=$!
		echo $PID > $PID_0
	fi
	if [ ! -f $PID_1 ] && $(ifconfig mon1 &> /dev/null); then
		(tcpdump -i mon1 -s 150 -U -w - 2> /dev/null | lzop -1 > ${DEST}/${TITLE}-mon1.pcap.lzop) &
		PID=$!
		echo $PID > $PID_1
	fi
}

Register_tracing() {
	PID_0=/var/run/registertrace_0.pid
	PID_1=/var/run/registertrace_1.pid
	DEBUG_PATH_0=/sys/kernel/debug/ieee80211/phy0/bluse 
	DEBUG_PATH_1=/sys/kernel/debug/ieee80211/phy1/bluse
	if [ ! -f $PID_0 ] && [ -f "$DEBUG_PATH_0"/reg_interval ]; then
		(tail -f ${DEBUG_PATH_0}/reg_log | lzop > ${DEST}/${TITLE}-mon0.register.lzop) &
		PID=$!
		echo $PID > $PID_0
	fi
	if [ ! -f $PID_1 ] && [ -f "$DEBUG_PATH_1"/reg_interval ]; then
		(tail -f ${DEBUG_PATH_1}/reg_log | lzop > ${DEST}/${TITLE}-mon1.register.lzop) &
		PID=$!
		echo $PID > $PID_1
	fi
}

Minstrel_Blues_tracing() {
	PID_0=/var/run/rc-stats.pid
	if [ ! -f $PID_0 ]; then
		( while true; do
			for tmp in /sys/kernel/debug/ieee80211/phy0/netdev:*/stations/*/rc_stats; do
				if [ -f "$tmp" ]; then
					mactmp="${tmp%/*}"
					mac="${mactmp##*/}"
					echo "neighbor: $mac"  >> ${DEST}/${TITLE}.rcstats
					cat < $tmp 2> /dev/null  >> ${DEST}/${TITLE}.rcstats
		                fi
		        	usleep 50000
		       	done
		done) &
		PID=$!
		echo $PID > $PID_0
	fi
}

System_tracing() {
	PID_0=/var/run/system-load.pid
	if [ ! -f $PID_0 ]; then
		(cpusage 2>&1 | lzop -1 > ${DEST}/${TITLE}.cpuload.lzop) &
		PID=$!
		echo $PID > $PID_0
	fi                           	
}

#start all trace functions
start() {
	echo "save node configuration"
	Save_config $TITLE
	echo "starting Pcap tracing"
	Pcap_tracing $TITLE
	echo "starting Register tracing"
	Register_tracing $TITLE
	echo "starting Minstrel Blues tracing"
	Minstrel_Blues_tracing $TITLE
	echo "starting System tracing"
	System_tracing $TITLE
	echo "done"
}

stop() {
	[ -f /var/run/tcpdump_0.pid ] && kill $(cat /var/run/tcpdump_0.pid) > /dev/null 2>&1 && rm /var/run/tcpdump_0.pid
	[ -f /var/run/tcpdump_1.pid ] && kill $(cat /var/run/tcpdump_1.pid) > /dev/null 2>&1 && rm /var/run/tcpdump_1.pid
	[ -f /var/run/registertrace_0.pid ] && kill $(cat /var/run/registertrace_0.pid) > /dev/null 2>&1 && rm /var/run/registertrace_0.pid
	[ -f /var/run/registertrace_1.pid ] && kill $(cat /var/run/registertrace_1.pid) > /dev/null 2>&1 && rm /var/run/registertrace_1.pid
	[ -f /var/run/rc-stats.pid ] && kill $(cat /var/run/rc-stats.pid) > /dev/null 2>&1 && rm /var/run/rc-stats.pid
	[ -f /var/run/system-load.pid ] && kill $(cat /var/run/system-load.pid) > /dev/null 2>&1 && rm /var/run/system-load.pid
	killall tcpdump tail cpusage lzop cat usleep
}

case "$1" in 
	start)
		   #safe on cf card as default
		   TITLE=${2:-test-run}
		   start $TITLE
  	;; 
	stop) 
	   stop 
	;; 
	restart)
		stop
		start
	;;
	*) 
		echo "Usage: $0 {start|stop|restarti exp.titel}" 
esac 







