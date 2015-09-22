#!/bin/bash
#
# Minstrel Attenuator experiment
# ------------------------------  
#
# Goal: comparing default and channel coherence time based 
# Minstrel Rate Control implementations by simulating channel attenuation
# with a USB attenuator device.

# Parameters:
MODE=${1:-all}					# all, init, sim(ulate)
NAME=${2:-rhapsody_ani=off_rtc}

## Configuration:
ANI=0						# 0 = "off", 1 = "on"

ATT_CTRL="./attenuator_lab_brick"		# attenuator control executable
ATT_LOG="attenuator.log"
ATTENUATE_LOW="0"				# dBm, lower bound for att.
ATTENUATE_HIGH="30"				# dBm, upper bound for att.

DATETIME=`date +'%Y/%m/%d %H:%M:%S'`		# now
TIMESTR=`date +'%Y-%m-%d_%H-%M-%S'`		# now
EXPERIMENT="${NAME}-${ATTENUATE_HIGH}dBm"	# experiment name
LOGDIR="logs/"					# experiment log files go here
LOGFILE="${LOGDIR}$EXPERIMENT-${TIMESTR}.log"	# logfile for this experiment

INTERVAL=240					# interval for each single run 
						# of a CCT, packet size/rate tuple 
CHANNEL=40					# use this wireless channel
IPERF_PORT=12000				# iperf TCP/UDP port

ETH_CTRL=10.1.0.202				# Laptop
ETH_AP=10.1.0.1
WLAN_AP=10.10.0.1				# WiFi IP of AP node
ETH_STA=10.1.0.2
WLAN_STA=10.10.0.2				# WiFi IP of client node
WLAN_TXPOWER=0					# use this txpower for both
						# client and AP
WLAN_BC=10.10.0.255				# broadcast address for hping
						# markers
DIR_TRACES="./traces/"				# general trace directory

DIR_EXP="${DIR_TRACES}/${NAME}"			# traces for this experiment
						# series


#CCT_INTERVALS="20000 12 24 50 100 1000"		# send iperf traffic for each
#						# amount of milliseconds
CCT_INTERVALS="20000 50 100 1000"		# send iperf traffic for each
						# amount of milliseconds
PACKET_SIZES="1500"				# different packet sizes in b
						# (UDP only!)
PACKET_RATES="50 200 600 1200"			# packet rates in packets/s
						# (UDP only!)
TCPDATA="500MB"					# amount of data sent by iperf
						# as TCP stream

RUNS=1						# run each round so many times


PID_SUBS=""					# kill all these when stopped by
						# Ctrl+C

PID_ATT_CTRL=0					# kill attenuator control tool
						# if running in background

ALERT="/usr/bin/mplayer -really-quiet `pwd`/siren.wav &"

## Clean-up on exit:
trap 'for pid in $PID_SUBS; do echo "Terminating $pid ..."; kill -9 $pid; done;  if [ $PID_ATT_CTRL -ne 0 ]; then kill $PID_ATT_CTRL; fi; exit 1' SIGINT SIGTERM

mkdir logs/ 2>/dev/null

## Functions:
function LOG {
	SUCC=""
	if [ ! -z "$2" ]; then
		if [ $2 -ne 0 ]; then
			SUCC=" [FAIL]"
		else
			SUCC=" [ OK ]"
		fi
	fi

	if [ "$MODE" == "all" ] || [ "$MODE" == "init" ]; then
		echo "$(date +%H:%M:%S):${SUCC} $1" | tee -a $LOGFILE
	fi
	if [ "$MODE" == "sim" ]; then
		echo "LOG: $(date +%H:%M:%S):${SUCC} $1"
	fi
}

function SLEEP {
	DURATION="$1"
	if [ "$MODE" == "all" ] || [ "$MODE" == "init" ]; then
		sleep $DURATION
	fi
	if [ "$MODE" == "sim" ]; then
		echo "sleep: $DURATION s"
	fi
}

function CMD {
	HOST="$1"
	SHELLCMD="$2"
	LOG "ssh on $HOST: $SHELLCMD"
	if [ "$MODE" == "all" ] || [ "$MODE" == "init" ]; then
		ssh -o StrictHostKeyChecking=no root@$HOST ''$SHELLCMD'' 2>&1 | tee -a $LOGFILE
	fi
	if [ "$MODE" == "sim" ]; then
		echo "CMD: ssh -o StrictHostKeyChecking=no root@$HOST '$SHELLCMD' 2>&1" 
	fi
}

function MKDIR {
	DIRNAME="$1"
	if [ -n "${DIRNAME}" ] && [ ! -d "${DIRNAME}" ]; then
		LOG "creating directory '${DIRNAME}'"
		mkdir "${DIRNAME}"
	fi
}

function NCX {
	local res=1
	HOST="$1"
	PORT="$2"
	SHELLCMD="$3"
	LOG "nc on $HOST:$PORT: $SHELLCMD"
	while [ ${res} -ne 0 ]; do
		if [ "$MODE" == "all" ] || [ "$MODE" == "init" ]; then
			echo "$SHELLCMD" | nc -v $HOST $PORT | tee -a $LOGFILE
			res=${PIPESTATUS[1]}
		fi
		if [ "$MODE" == "sim" ]; then
			echo "NCX @ $HOST:$PORT: $SHELLCMD"
			res=0
		fi
		SLEEP 1
	done
}

function SCP {
	FILE="$1"
	HOST="$2"
	DEST="${3:-/tmp/}"
	LOG "copying $FILE to $HOST:$DEST"
	if [ "$MODE" == "all" ] || [ "$MODE" == "init" ]; then
		scp -o StrictHostKeyChecking=no "$FILE" root@$HOST:$DEST 2>&1 | tee -a $LOGFILE
	fi
	if [ "$MODE" == "sim" ]; then
		echo "scp -o StrictHostKeyChecking=no $FILE root@$HOST:$DEST"
	fi
}

function BC {
	
	BC_MSG="$1"
	NCX $ETH_AP 8003 "/usr/sbin/hping3 ${WLAN_BC} --udp --baseport 8888 --destport 8888 -e \"${BC_MSG}\" -c 1 --fast 2>/dev/null 1>/dev/null ; exit"
#	NCX $ETH_STA 8003 "/usr/sbin/hping3 ${WLAN_BC} --udp --baseport 8888 --destport 8888 -e \"${BC_MSG}\" -c 1 --fast 2>/dev/null 1>/dev/null ; exit"
}

function attenuate {
	STEP_TIME="$1"				# interval length in ms
	ATT_DESC=${2:-unknown}
	DB_LOW="${3:-$ATTENUATE_LOW}"		# lower bound
	DB_HIGH="${4:-$ATTENUATE_HIGH}"		# upper bound

	# generate temporary csv file for this setup:
	ATT_CFG="./wf_att.csv"
	touch "${ATT_CFG}"
	echo -n "" > "${ATT_CFG}"
	echo "${STEP_TIME};${DB_LOW}" > "${ATT_CFG}"
	echo "${STEP_TIME};${DB_HIGH}" >> "${ATT_CFG}"

	BC "START_ATT=${DB_HIGH}"

	ATT_LOG="./attenuator/attenuator_${ATT_DESC}.log"
	if [ $STEP_TIME -lt 50 ]; then
		ATT_LOG=""
		LOG "disabling attenuator log due to interval being too short"
	fi
	# modify attenuator:
	if [ "$MODE" == "all" ]; then
		if [ -n "$ATT_LOG" ]; then
			rm "${ATT_LOG}" 2>/dev/null
			touch "${ATT_LOG}"
			LOG "preparing attenuator log file" $?

			LOG "# sudo ${ATT_CTRL} -r ms -f ${ATT_CFG} -l ${ATT_LOG}"
			#./attenuator_lab_brick -r ms -f wf_att.csv -l $LOGFILE > /dev/null & 
			sudo "${ATT_CTRL}" -r ms -f "${ATT_CFG}" -l "${ATT_LOG}" > /dev/null &
			PID_ATT_CTRL=$!
		else
			LOG "# sudo ${ATT_CTRL} -r ms -f ${ATT_CFG}"
			sudo "${ATT_CTRL}" -r ms -f "${ATT_CFG}" > /dev/null &
			PID_ATT_CTRL=$!
#			sudo "${ATT_CTRL}" -r ms -f "${ATT_CFG}" &
		fi
		LOG "starting attenuation: ${DB_LOW} <-> ${DB_HIGH}, PID: $PID_ATT_CTRL"
		SLEEP 5				# the tool needs some time 
						# to start up
	fi
	if [ "$MODE" == "sim" ]; then
		echo "== Round attenuate: sudo $ATT_CTRL -r ms -f ${ATT_CFG} -l ${ATT_LOG}"
		cat "${ATT_CFG}"
	fi
}

function stop_attenuate {

	if [ "$MODE" == "all" ]; then
		if [ $PID_ATT_CTRL -ne 0 ]; then
			kill $PID_ATT_CTRL 2> /dev/null
			LOG "terminating Attenuator control (${PID_ATT_CTRL})" $?
			PID_ATT_CTRL=0
			mkdir "${DIR_EXP}/attenuator/" 2>/dev/null
			mv "${ATT_LOG}" "${DIR_EXP}/attenuator/" 2>/dev/null
			LOG "copying attenuator log file to traces" $?
		fi
	fi
}

## Experiment summary for log-file:
cat > "$LOGFILE" << EOF
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
Experiment:
	"$EXPERIMENT"
	Minstrel channel coherence based rate control

Setup:
	Two PCEngines Alix nodes set up on a table, one as AP
	and the other one acting as a station where the AP is sending iperf
	traffic to the STA. (download scenario).

	iperf		iperf
	sending ----->	receiving
	[ ap ]		[ sta ]

	The measurement invovles multiple packet sizes ($PACKET_SIZES) for both
	TCP and UDP. For each packet size, TCP transmits $TCPDATA while UDP
	packets are sent with multiple packet rates ($PACKET_RATES pkt/s)
	for the duration of $INTERVAL s.

		AP		sta
	lan	$ETH_AP		$ETH_STA
	wifi	$WLAN_AP	$WLAN_STA

	In this setup, we simulate changes to the channel by using a Vaunix
	Lab Brick Digital Attenuator and alternating between +${ATTENUATE_LOW}
	and +${ATTENUATE_HIGH} dBm attenuation.

	The channel coherence time (= time between attenuation switches) is
	measured for each of the following durations:
	$CCT_INTERVALS
	We perform $RUNS runs for each interval setting.

Time:
	$DATETIME

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

EOF

## Initialization (copy scripts to node, start monitor interfaces)

echo "logging to file $LOGFILE"

if [ "$MODE" == "init" ] || [ "$MODE" == "all" ]; then

	LOG "checking files and directories ..."
	test -f "${ATT_CTRL}"
	RES=$?
	LOG "attenuator control tool" $RES
	if [ $RES -ne 0 ]; then
		LOG "Error: attenuator control tool missing. Please build and copy it to '${ATT_CTRL}'!"
		exit 1
	fi
	MKDIR "${DIR_TRACES}"	
	MKDIR "./attenuator/"	

	LOG "copying files ..."
	SCP files/add_monitor.sh $ETH_AP "/usr/sbin/add_monitor"
	SCP files/measurement.sh $ETH_AP "/etc/init.d/"
	SCP files/measurement.sh $ETH_AP "/usr/sbin/measurement"
	SCP files/ani $ETH_AP "/usr/sbin/ani"
#	SCP files/ath5k_set_antenna $ETH_AP "/usr/sbin/"
#	SCP files/set_ani $ETH_AP "/usr/sbin/"
	SCP files/netcat-trace-server $ETH_AP "/etc/init.d/"

	SCP files/add_monitor.sh $ETH_STA "/usr/sbin/add_monitor"
	SCP files/measurement.sh $ETH_STA "/etc/init.d/"
	SCP files/measurement.sh $ETH_STA "/usr/sbin/measurement"
	SCP files/ani $ETH_STA "/usr/sbin/ani"
#	SCP files/ath5k_set_antenna $ETH_STA "/usr/sbin/"
#	SCP files/set_ani $ETH_STA "/usr/sbin/"
	SCP files/netcat-trace-server $ETH_STA "/etc/init.d/"

	LOG "setting up monitor interfaces ..."
	CMD $ETH_STA "add_monitor"
	CMD $ETH_AP "add_monitor"

#	LOG "configuring interfaces ..."
#	CMD $ETH_STA "iwconfig wlan0 txpower $WLAN_TXPOWER"
#	CMD $ETH_AP "iwconfig wlan0 txpower $WLAN_TXPOWER"
fi
if [ "$MODE" == "init" ]; then
	LOG "initialization complete, exiting ..."
	exit 0
fi

## Start of experiment:
LOG "starting experiment ..."

mkdir "${DIR_EXP}" 2>/dev/null
LOG "creating directory '${DIR_EXP}'" $?


if [ ${ANI} -eq 1 ]; then
	LOG "turning ANI on"
else
	LOG "turning ANI off"
fi
CMD $ETH_STA "ani ${ANI}"
CMD $ETH_AP "ani ${ANI}"

SLEEP 5

ROUND=1
PROTO="tcp"

LOG "--- measuring TCP ---"

LOG "stopping all previous iperf instances"
CMD $ETH_AP "killall iperf 2>/dev/null"
CMD $ETH_STA "killall iperf 2>/dev/null"

IPERF_LOCK=/tmp/iperf.lock

LOG "stopping all previous iperf instances"
CMD $ETH_AP "/etc/init.d/netcat-trace-server restart 10"
CMD $ETH_STA "/etc/init.d/netcat-trace-server restart 10"

for cct in $CCT_INTERVALS; do
#	LOG "synchronizing time via NTP"
#	NCX $ETH_AP 8008 "ntpdate ${ETH_CTRL}; exit" 
#	NCX $ETH_STA 8008 "ntpdate ${ETH_CTRL}; exit" 
	SLEEP 5

	attenuate $cct "proto=tcp_cct=$cct"

	size="$PACKET_SIZES"
	for run in `seq 1 $RUNS`; do

		LOG "starting TCP iperf server on $ETH_STA"
		NCX $ETH_STA 8001 "/usr/bin/iperf -s -p $IPERF_PORT; exit" &
		PID_SUBS="$! $PID_SUBS"

		LOG "restarting wifi on $ETH_STA ..."
		NCX $ETH_STA 8002 "wifi; exit"
		SLEEP 20

		NCX $ETH_STA 8009 "add_monitor; exit"

		EXPDESC="round=${ROUND}_proto=${PROTO}_size=${size}_data=${TCPDATA}_cct=${cct}_run=${run}"
		LOG "== Round $ROUND: $EXPDESC"

		CMD $ETH_AP "/etc/init.d/measurement.sh start $EXPDESC"
		CMD $ETH_STA "/etc/init.d/measurement.sh start $EXPDESC"
		SLEEP 5

		BC "START_$EXPDESC"
		SLEEP 2
		LOG "iperf: starting on AP"
		NCX $ETH_AP 8004 "touch $IPERF_LOCK; iperf -c $WLAN_STA -p $IPERF_PORT -n ${TCPDATA}; rm $IPERF_LOCK; exit"

		LOG "iperf: client done on AP"

		BC "STOP_$EXPDESC"

		CMD $ETH_AP "/etc/init.d/measurement.sh stop"
		CMD $ETH_STA "/etc/init.d/measurement.sh stop"

		LOG "stopping all iperf instances ..."
		NCX $ETH_STA 8007 "killall iperf 2>/dev/null; exit"
		NCX $ETH_AP 8007 "killall iperf 2>/dev/null; exit"

	done	# runs
	LOG "collecting traces ..."
	if [ "$MODE" == "all" ]; then
		./collect.sh "${DIR_EXP}"
	fi

	stop_attenuate
	SLEEP 20
	ROUND=$[ROUND + 1]
done	# cct

LOG "stopping netcat-trace-servers ..."
CMD $ETH_AP "/etc/init.d/netcat-trace-server stop"
CMD $ETH_STA "/etc/init.d/netcat-trace-server stop"

SLEEP 2
LOG "collecting traces ..."
if [ "$MODE" == "all" ]; then
	./collect.sh "${DIR_EXP}"
fi

cp "${LOGFILE}" "${DIR_EXP}"
LOG "copying log file to traces" $?

LOG "done."
$ALERT

exit 0

LOG "--- measuring UDP ---"
PROTO="udp"

for cct in $CCT_INTERVALS; do
#	LOG "synchronizing time via NTP"
#	NCX $ETH_AP 8008 "ntpdate ${ETH_CTRL}; exit" 
#	NCX $ETH_STA 8008 "ntpdate ${ETH_CTRL}; exit" 
	SLEEP 5

	attenuate $cct "proto=udp_cct=$cct"

	size="$PACKET_SIZES"

	CMD $ETH_AP "/etc/init.d/netcat-trace-server restart 10"
	CMD $ETH_STA "/etc/init.d/netcat-trace-server restart 10"

	for rate in $PACKET_RATES; do

		for run in `seq 1 $RUNS`; do
			LOG "starting UDP iperf server on $ETH_STA"
			NCX $ETH_STA 8001 "iperf -s -u -p $IPERF_PORT 2>/dev/null ; exit" &

			LOG "restarting wifi on $ETH_STA ..."
			NCX $ETH_STA 8002 "wifi; exit"
			SLEEP 20

			NCX $ETH_STA 8009 "add_monitor; exit"

			BITSPERSEC=`echo $size*8*$rate | bc`
			EXPDESC="round=${ROUND}_proto=${PROTO}_size=${size}_packetrate=${rate}_cct=${cct}_run=${run}"
			LOG "== Round $ROUND: $EXPDESC"

			CMD $ETH_AP "/etc/init.d/measurement.sh start $EXPDESC"
			CMD $ETH_STA "/etc/init.d/measurement.sh start $EXPDESC"

			BC "START_$EXPDESC"
			NCX $ETH_AP 8004 "touch $IPERF_LOCK; iperf -u -c $WLAN_STA -p $IPERF_PORT -l ${size}B -b $BITSPERSEC -t $INTERVAL; rm $IPERF_LOCK; exit"

			BC "STOP_$EXPDESC"

			CMD $ETH_AP "/etc/init.d/measurement.sh stop"
			CMD $ETH_STA "/etc/init.d/measurement.sh stop"

			LOG "stopping all iperf instances ..."
			NCX $ETH_STA 8007 "killall iperf 2>/dev/null; exit"
			NCX $ETH_AP 8007 "killall iperf 2>/dev/null; exit"
		done	# runs
		ROUND=$[ROUND + 1]

		LOG "collecting traces ..."
		if [ "$MODE" == "all" ]; then
			./collect.sh "${DIR_EXP}"
		fi
	done	# rates

	stop_attenuate

	SLEEP 20

done	# cct
LOG "stopping netcat-trace-servers ..."
CMD $ETH_AP "/etc/init.d/netcat-trace-server stop"
CMD $ETH_STA "/etc/init.d/netcat-trace-server stop"

SLEEP 2
LOG "collecting traces ..."
if [ "$MODE" == "all" ]; then
	./collect.sh "${DIR_EXP}"
fi

cp "${LOGFILE}" "${DIR_EXP}"
LOG "copying log file to traces" $?

LOG "done."
$ALERT

