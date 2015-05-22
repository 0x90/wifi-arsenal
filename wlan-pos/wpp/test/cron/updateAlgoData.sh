#!/bin/bash

VENV_HOME=/opt/wpp
WPP_HOME=$VENV_HOME/src/wpp
LOGDIR=$WPP_HOME/log

. $VENV_HOME/bin/activate

datetime=`date +%Y-%m%d`
timestamp=`date +%Y-%m%d-%H%M%S`
thisfilename=`basename $0 |awk -F. '{print $1}'`

task_banner="\n========= TASK:$thisfilename WAKEUP@$timestamp ========"
[ -d $LOGDIR ] || mkdir -p $LOGDIR
echo -e $task_banner  >> $LOGDIR/upalgodb_$datetime.log 2>&1

export PYTHONPATH=$WPP_HOME
cd $WPP_HOME/wpp
python offline.py -u >> $LOGDIR/upalgodb_$datetime.log 2>&1
