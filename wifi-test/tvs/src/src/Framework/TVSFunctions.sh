# Copyright (c) <2002>, Intel Corporation
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the following 
# conditions are met:
# 
# Redistributions of source code must retain the above copyright 
# notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright 
# notice, this list of conditions and the following disclaimer in
# the documentation and/or other materials provided with the distribution.
# 
# Neither the name of Intel Corporation, nor the names 
# of its contributors may be used to endorse or promote products 
# derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
# OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

###############################################
# $Id: TVSFunctions.sh,v 1.5 2004/05/08 06:36:08 xling Exp $
# TVS_TestPurposeStart:
# The first thing that all test purposes written 
# in shell script will need to do is call this 
# function.  
#
# $0: Title
# $1: Description
# $2: Owner's Email Address
# $3: MANDITORY|OPTIONAL
# ==============================================
TVSCONTROLLER=TVSController
TVSVARDIR="/var/tvs"
TVS_TestPurposeStart()
{
    tet_infoline "$*"
    TVS_FAIL=N
    echo $TET_RESFILE > $TVS_ROOT/var/resfile
    sync
}
tvs_test_purpose_start()
{
    tet_infoline "$*"
    TVS_FAIL=N
    echo $TET_RESFILE > $TVS_ROOT/var/resfile
    sync
}
################################################
# TVS_TestPurposeFinish:
# This should be the last thing that all test 
# purposes written in shell script should do.
# 
# $0 PASS|FAIL
# $1 Comment
# ==============================================
tvs_test_purpose_finish()
{
    # $1 is result code to give if TVS_FAIL=N (default PASS)
    if [ $TVS_FAIL = N ]
    then
	tet_result ${1-PASS}
    else
	tet_result ${1-PASS}
    fi
}
TVS_TestPurposeFinish()
{
    # $1 is result code to give if TVS_FAIL=N (default PASS)
    if [ $TVS_FAIL = N ]
    then
	tet_result ${1-PASS}
    else
	tet_result FAIL
    fi
}

TVS_RequestRestart()
{
    tet_infoline "Sending HUP to TVSController..."
    tet_result RESTART
    tet_tpend $TET_TPNUMBER
    killall -HUP $TVSCONTROLLER
}
function tvs_request_restart()
{
    tvs_reboot_now
}
function tvs_reboot_now {
    TVS_RequestRestart
}

function tvs_end_restart {
    > $TVSVARDIR/tvsrestartnext
    killall -HUP $TVSCONTROLLER
}
function tvs_exit_scenario {
    tet_infoline "To exit current scenario..."
#    tet_tpend $TET_TPNUMBER
    tet_output 220 "$TET_TPNUMBER 101 `date +%H:%M:%S`" "FATAL"
    > $TVSVARDIR/tvsexitscen
    killall -HUP $TVSCONTROLLER
}

function tvs_exit_suite {
    tet_infoline "To exit current suite..."
    tet_output 220 "$TET_TPNUMBER 101 `date +%H:%M:%S`" "FATAL"
    > $TVSVARDIR/tvsexitsuite
    killall -HUP $TVSCONTROLLER
}

function tvs_set_rerun_on_crash {
    tet_infoline "Setting crash on rerun..."
    killall -TRAP $TVSCONTROLLER
}

function tvs_unset_rerun_on_crash {
    tet_infoline "Unsetting crash on rerun..."
    killall -ILL $TVSCONTROLLER
}

###########################
# Make TVS restart n times
function tvs_restart_ntimes()
{
    RERUN_TIMES=${1:-1}
    TMPFILE="$TVSVARDIR/tvsrun.count"
    if [ ! -e $TMPFILE ]; then
	tet_infoline "First run, setting count to $RERUN_TIMES..."
        echo $RERUN_TIMES > $TMPFILE
    fi

    COUNT=`cat $TMPFILE`
    COUNT=${COUNT:=1}
    if [ "0" = $COUNT ]; then
	tet_infoline "Done restarting."
	rm $TMPFILE

	exit
    fi

    tet_infoline "Decrementing count from $COUNT..."
    #dc -e "$COUNT 1 - n" > $TMPFILE
    expr $COUNT - 1 > $TMPFILE
    
    # In order to make this test reboot:
    # 1. Turn on TVS_REBOOT_ON_RESTART 
    #    in /etc/TVSEnvironment
    # 2. uncomment the line below
    TVS_RequestRestart PASS
}

function tvs_set_timeout()
{
    TIMEOUT=${1:-600}
    $TVS_ROOT/bin/wdtdm i $TIMEOUT    
    tet_infoline "Set $TIMEOUT second timeout"
    echo "Set $TIMEOUT second timeout"
}











