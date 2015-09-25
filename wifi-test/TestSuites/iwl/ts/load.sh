#!/bin/bash
#
#Copyright (c) 2006 - 2009, Intel Corporation
#Author: Jeff Zheng <jeff.zheng@intel.com>
#Contact: WiFi Test Development <wifi-test-devel@lists.sourceforge.net>
#
#This program is free software; you can redistribute it and/or 
#modify it under the terms of the GNU General Public License version 
#2 as published by the Free Software Foundation.
#
#This program is distributed in the hope that it will be useful, but 
#WITHOUT ANY WARRANTY; without even the implied warranty of 
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
#General Public License for more details.
#
#You should have received a copy of the GNU General Public License 
#along with this program; if not, write to the Free Software Foundation, 
#Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
#

set -x 
tet_startup="startup"    	   # startup function
tet_cleanup="cleanup"    	   # cleanup function

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14"

ic1="INST"
ic2="LOAD2"
ic3="LOAD3"
ic4="LOAD7"
ic5="LOAD8"
ic6="LOAD9_1"
ic7="LOAD9_2"
ic8="LOAD10_1"
ic9="LOAD10_2"
ic10="LOAD11"
ic11="LOAD12"
ic12="LOAD13"
ic13="LOAD14_1"
ic14="LOAD14_2"

#============ load module
INST()
{
    tpstart "load module"
    iwl_load_module
    ifconfig wlan0 up
    iwlist wlan0 scan |grep Cell
    [ $? == 0 ] || iwl_fail "Failed to load module"
    tpresult
}

#============
LOAD2()
{
    tpstart "unload module"
    iwl_load_module
    sleep 4
    ifconfig wlan0 up
    modprobe iwl4965 -r
    modprobe iwl3945 -r 
    sleep 4
    n=`lsmod |grep -i iwl |wc -l`
    [ $n -eq 0 ] || iwl_fail "Failed to unload module"
    tpresult
}

#============
LOAD3()
{
    tpstart "Software RF Kill"
    iwl_load_module
    #iwl_test || { iwl_fail; break; }
    sleep 5
    if [ -d /sys/bus/pci/drivers/iwl3945/0000:03:00.0 ] 
    then 
        cd /sys/bus/pci/drivers/iwl3945/0000:03:00.0/rfkill:rfkill*
    else
        cd /sys/bus/pci/drivers/iwlagn/0000:0[123]:00.0/rfkill:rfkill*
    fi
    dir=`pwd`
    [ -f $dir/state ] || iwl_fail "No rf_kill file"
    rf_kill=`cat $dir/state`
    [ "$rf_kill" == 1 ] || iwl_fail "rf_kill value wrong"
    echo 0 > $dir/state
    sleep 5
    cat $dir/state
    rf_kill=`cat $dir/state`
    [ "$rf_kill" == 0 ] || iwl_fail "rf_kill value wrong"
    iwlist wlan0 scan |grep Cell
    [ $? == 0 ] && iwl_fail "Can scan when rf_kill available"
    tpresult
}

#============
LOAD7()
{
    tpstart "Hardware scan"
    mod_option="disable_hw_scan=0"
    iwl_load_module
    ifconfig wlan0 up
    n=`iwlist wlan0 scan |grep Cell |wc -l`
    [ $n -lt 10 ] && iwl_fail "Too few APs scaned"
    tpresult
}

#============
LOAD8()
{
    tpstart "Software scan"
    mod_option="disable_hw_scan=1"
    iwl_load_module
    ifconfig wlan0 up
    n=`iwlist wlan0 scan |grep Cell |wc -l`
    [ $n -lt 10 ] && iwl_fail "Too few APs scaned"
    tpresult
}

#============
LOAD9_1()
{
    tpstart "WPA2 EAP PEAP AES-CCMP (HW)"
    is3945 && mod_option="swcrypto=0"
    is4965 && mod_option="swcrypto=0"
    is5000 && mod_option="swcrypto50=0"
    wpa2 2 2 1 1 2 1
}
#============
LOAD9_2()
{
    tpstart "WPA EAP PEAP TKIP (HW)"
    is3945 && mod_option="swcrypto=0"
    is4965 && mod_option="swcrypto=0"
    is5000 && mod_option="swcrypto50=0"
    wpa2 1 2 2 2 2 1
}

#============
LOAD10_1()
{
    tpstart "WPA PSK TKIP (SW)" 
    is3945 && mod_option="swcrypto=1"
    is4965 && mod_option="swcrypto=1"
    is5000 && mod_option="swcrypto50=1"
    wpa2 1 1 2 2 0 0 
}

#============
LOAD10_2()
{
    tpstart "WPA2 PSK CCMP (SW)" 
    is3945 && mod_option="swcrypto=1"
    is4965 && mod_option="swcrypto=1"
    is5000 && mod_option="swcrypto50=1"
    wpa2 2 1 1 1 0 0
}

LOAD11()
{
    tpstart "Hardware queues"
    is3945 && queues=(10 11 12 13 14 15 16)
    is4965 && queues=(10 11 12 13 14 15 16)
    is5000 && queues=(10 11 12 13 14 15 16 17 18 19 20)
    for queue in ${queues[@]}
    do
        is3945 && mod_option="queues_num=$queue"
        is4965 && mod_option="queues_num=$queue"
        is5000 && mod_option="queues_num50=$queue"
        iwl_load_module
        iwl_test || iwl_fail
    done   	
    tpresult
}

LOAD12()
{
    tpstart "Disable 11n functionality"
    is3945 && mod_option="11n_disable=1"
    is4965 && mod_option="11n_disable=1"
    is5000 && mod_option="11n_disable50=1"
    iwl_load_module
    iwl_test -a open -b enable -w enable -k 1 || iwl_fail
    tpresult
}

LOAD13()
{
    tpstart "AMSDU Size"
    is3945 && mod_option="amsdu_size_8K=0"
    is4965 && mod_option="amsdu_size_8K=0"
    is5000 && mod_option="amsdu_size_8K50=0"
    iwl_load_module
    iwl_test || iwl_fail
    tpresult
}

LOAD14_1()
{
    tpstart "Antenna=1"
    mod_option="antenna=1"
    iwl_load_module
    iwl_test || iwl_fail
    tpresult
}
LOAD14_2()
{
    tpstart "Antenna=2"
    mod_option="antenna=2"
    iwl_load_module
    iwl_test || iwl_fail
    tpresult
}


startup() # start-up function()
{
    tet_infoline "Inside startup..."
    mkdir -p $TMPDIR
}

cleanup() # clean-up function()
{
    tet_infoline "Inside cleanup..."
}

. iwl_wpacommon.sh
. iwl_common.sh
iwl_load_module()
{
    pkill -9 wpa_supplicant
    rm -rf /var/run/wpa_supplicant
    ifconfig wlan0 down
    modprobe iwlagn -r
    modprobe iwl3945 -r
    sleep 2
    is3945 && modprobe iwl3945 $mod_option
    isagn && modprobe iwlagn $mod_option
    sleep 4
}

. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
       	
