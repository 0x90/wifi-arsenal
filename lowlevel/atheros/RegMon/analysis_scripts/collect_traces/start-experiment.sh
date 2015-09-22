#!/bin/sh

#
# Experimentation script
# T.Huehn Dez.2011

BOWLMUSSH=/data/nfs/bowl_measurement_area/bowl-mussh
USBDIR=/data/usbstick/experiment
EXPDIR=$(pwd)
NODELIST=$EXPDIR/asus-node-list-v2.txt
LOGFILE=$EXPDIR/experiment-logfile.log
MUSSH="/usr/local/bin/mussh -P -m20 -s /bin/ash -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -l root"


#log function to have a global logfile
_LOG () {
	echo "$(date +"%T-%d.%m.%Y") $*" | tee -a $LOGFILE
}

#set a marker in each syslogfile per node to grep all syslog messages for the experiment duration
_SYSLOG_STARTID () {
	$BOWLMUSSH -H $NODELIST -c ""
}

#helper function to start stop all traceproducers
_TRACING () {
	$BOWLMUSSH -H $NODELIST -c "/etc/init.d/registertrace $1; \
				/etc/init.d/clicksniff $1; \
				/etc/init.d/athtrace $1; \
				/etc/init.d/collectd $1" $> /dev/zero
	_LOG "status=$1 for clicksniff, athtrace, registertrace, collectd"
	sleep 1
}

#clear the usb space 
_CLEAR_USB () {
	$BOWLMUSSH -H $NODELIST -c "$USBDIR/scripts/clear-usb-data.sh" $> /dev/zero
	_LOG "USB trace&config&collectd folders are cleared"	
}

#store each node configuration 
_STORE_NODECONFIG () {
	$BOWLMUSSH -H $NODELIST -c "dump_config $USBDIR/config"
	_LOG "all node configurations are stored"	
}

#start click broadcaster
_START_SENDER () {
	_LOG "*** node $1 is broadcasting packets now***"
	ssh -i /tmp/id_smoketest root@$1 "$USBDIR/scripts/start_broadcasting.sh"
	_LOG "*** node $1 stoped broadcasting ***"
}

#start txcont interferer with rate and power
_START_INTERFERER () {
	ssh -i /tmp/id_smoketest root@$1 "/usr/sbin/iwpriv ath0 txcontrate $2; /usr/sbin/iwpriv ath0 txcontpower $3; /usr/sbin/iwpriv ath0 txcont 1"
	_LOG "*** node $1 started txcont interference with rate $2 and power $3 ***"
}

#stop txcont interferer
_STOP_INTERFERER () {
	ssh -i /tmp/id_smoketest root@$1 "/usr/sbin/iwpriv ath0 txcont 0"
	_LOG "*** node $1 stoped txcont interference ***"
}

_CREATE_FOLDER_STRUCTURE () {
	mkdir -p $EXPDIR/data/ofdmweak-$1/sender=$2
	mkdir -p $EXPDIR/data/ofdmweak-$1/sender=$2/syslog
	mkdir -p $EXPDIR/data/ofdmweak-$1/sender=$2/collectd
	mkdir -p $EXPDIR/data/ofdmweak-$1/sender=$2/config
	mkdir -p $EXPDIR/data/ofdmweak-$1/sender=$2/traces
}

_BACKUP_TRACES () {
	local HOSTNAME='$(cat /proc/sys/kernel/hostname | cut -d'-' -f1)'
	#copy everything in one folder but not folder SCRIPTS, they have the same name
	$BOWLMUSSH -H $NODELIST -c "cp $USBDIR/traces/* $EXPDIR/data/ofdmweak-$1/sender=$2/traces/; \
				cp -R $USBDIR/collectd/* $EXPDIR/data/ofdmweak-$1/sender=$2/collectd/; \
				cp $USBDIR/config/* $EXPDIR/data/ofdmweak-$1/sender=$2/config/; \
				cp /var/log/messages $EXPDIR/data/ofdmweak-$1/sender=$2/syslog/$HOSTNAME-syslog.log "
	#TODO: chmod all files, because they are all readonly by root
	#TODO: copy script folder in individual folder"
	_LOG "Experiment data collected from nodes and stored on hdd"
}

#TODO


################################################################
### MAIN PART 
################################################################

echo " ****** experiment description: ***********

*_SETUP_*
-passiv noise measurement on channel 6 on BOWL ourdoor for 12 hours devided in 1 hour measurements
-node MA is used as the only beacon adhoc sender to synch the tsf timers on wifi and lan broadcaster
-channel 6 is observed
-the receiver node are set to use noiseimmunity = 0 (the other extreem is 4)
-cca threshold is set to 62 (the other extreem is 20)
-ofdm-weak detection is enabled
-periodic calibration rate = 0,1 Hz (each 10 sec)
-register sample rate = 1000Hz

*_GOAL_*
-how dynamic is the channel over time in terms of noise (but just measure with 0,1 Hz)

" > $LOGFILE

# start periodic calibration script on all nodes
$BOWLMUSSH -H $NODELIST -c "/etc/init.d/periodic-calibration start"
_LOG "periodic calibration started on all nodes"

#disable periodic calibration on the txcont sender node ma (calibration and txcont do not work together !!!)
#ssh -i /tmp/id_smoketest root@ma "/etc/init.d/periodic-calibration stop"
#_LOG "*** calibration disabled on txcont sender ma ***"

for HOUR in 0 1 2 3 4 5 6 7 8 9 11 12
do
        _LOG "We are in the $HOUR -th 12h part"

        _TRACING stop  #just to be sure

        #each node is a broadcast sender
        SENDER=ma
        _CREATE_FOLDER_STRUCTURE $HOUR $SENDER
        _LOG "Current broadcast transmitter is node $SENDER"
        _CLEAR_USB
        _STORE_NODECONFIG
        _TRACING start
        _START_SENDER $SENDER
        _TRACING stop
        _BACKUP_TRACES $HOUR $SENDER
done

#change the file permissions in order analyse them directly
ssh -i /tmp/id_smoketest root@ma "/bin/chmod -R 777 $EXPDIR/data/"
_LOG " ***** all /data/*.* filepermissions are changed - experiment done !!! "
