#!/bin/bash

VENV_HOME=/opt/wpp
WPP_HOME=$VENV_HOME/src/wpp
LOGDIR=$WPP_HOME/log/area

. $VENV_HOME/bin/activate

datetime=`date +%Y-%m%d`
timestamp=`date +%Y-%m%d-%H%M%S`
thisfilename=`basename $0 |awk -F. '{print $1}'`

task_banner="\n========= TASK:$thisfilename WAKEUP@$timestamp ========"
[ -d $LOGDIR ] || mkdir -p $LOGDIR
echo -e $task_banner  >> $LOGDIR/${thisfilename}_$datetime.log 2>&1

export PYTHONPATH=$WPP_HOME
cd $WPP_HOME/wpp
python offline.py -a >> $LOGDIR/${thisfilename}_$datetime.log 2>&1
