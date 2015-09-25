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

tet_startup="startup"            # startup function
tet_cleanup="cleanup"            # cleanup function

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14"
ic1="PMTX1"
ic2="PMTX2"
ic3="PMTX3"
ic4="PMTX4"
ic5="PMTX5"
ic6="PMTX6"
ic7="PMTX7"
ic8="PMTX8"
ic9="PMSUS1"
ic10="PMSUS2"
ic11="PMSUS4"
ic12="PMSUS5"
ic13="PMPSP1"
ic14="PMPSP2"

PMTX1()
{
    tpstart "BSS Switch Txpower"
    iwl_load_module
    iwl_test || { iwl_fail; break; }
    tet_infoline "Associate to AP success"
    tet_infoline "Set txpower to off"
    iwconfig wlan0 txpower off
    sleep 5
    ping -c 3 ${iwl_srv[1]} && { iwl_fail; break; }
    tet_infoline "ping to ${iwl_srv[1]} success"
    tet_infoline "Set txpower to on"
    iwconfig wlan0 txpower on
    sleep 5
    iwl_connect $@ && iwl_check  ${iwl_srv[1]} || { iwl_fail; break; }
    tet_infoline "Associate to AP success"
    tpresult
}


PMTX2()
{
    tpstart "IBSS Switch Txpower"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Set txpower to off"
    iwconfig wlan0 txpower off
    sleep 2
    tet_infoline "Set txpower to on"
    iwconfig wlan0 txpower on
    sleep 4
    iwl_connect -s $essid $@ -i && iwl_check ${iwl_peer[1]} || { iwl_fail; break; }
    tet_infoline "Ping ${iwl_peer[1]} success"
    tpresult
}

check_txpower_bss()
{
    for i in 1 4 10 15
    do
        tet_infoline "set txpower to $i"
        iwconfig wlan0 txpower $i
        sleep 4
        ping -c 3 ${iwl_srv[1]} || { iwl_fail; break; }
        tet_infoline "Ping ${iwl_srv[1]} with BSS success"
    done
}

check_txpower_ibss()
{
    for i in 1 4 10 15
    do
        tet_infoline "set txpower to $i"
        iwconfig wlan0 txpower $i
        sleep 4
        ping -c 3 ${iwl_peer[1]} || { iwl_fail; break; }
        tet_infoline "Ping ${iwl_peer[1]} with IBSS success"
    done
}

PMTX3()
{
    tpstart "IBSS Txpower"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    check_txpower_ibss
    tpresult
}

PMTX4()
{
    tpstart "IBSS Txpower with WEP40"
    iwl_load_module
    iwl_test_ibss  -w enable -k 1 || { iwl_fail; break; }
    check_txpower_ibss
    tpresult
}

PMTX5()
{
    tpstart "IBSS Txpower with WEP104"
    iwl_load_module
    iwl_test_ibss  -w enable -k 3 || { iwl_fail; break; }
    check_txpower_ibss
    tpresult
}

PMTX6()
{
    tpstart "BSS Txpower"
    iwl_load_module
    iwl_test || { iwl_fail; break; }
    check_txpower_bss
    tpresult
}

PMTX7()
{
    tpstart "BSS Txpower with WEP40"
    iwl_load_module
    iwl_test  -w enable -k 1 || { iwl_fail; break; }
    check_txpower_bss
    tpresult
}

PMTX8()
{
    tpstart "BSS Txpower with WEP104"
    iwl_load_module
    iwl_test  -w enable -k 3 || { iwl_fail; break; }
    check_txpower_bss
    tpresult
}

PMSUS1()
{
    tpstart "Suspend to RAM--BSS"
    iwl_load_module
    iwl_test || { iwl_fail; break; }
    tet_infoline "Associate to AP success"
    tet_infoline "Suspending..."
    # WHEN=`date +'%F %T' -d '+ 1minutes'`
    echo 0 > /sys/class/rtc/rtc0/wakealarm
    # echo "$WHEN" > /sys/class/rtc/rtc0/wakealarm
    echo "+50" > /sys/class/rtc/rtc0/wakealarm
    echo -n mem > /sys/power/state
    sleep 10
    # iwl_load_module
    tet_infoline "Resumed"
    iwl_test || { iwl_fail; break; }
    tet_infoline "Associate to AP success"
    tpresult
}

PMSUS2()
{
    tpstart "Suspend to Disk--BSS"
    iwl_load_module
    iwl_test || { iwl_fail; break; }
    tet_infoline "Associate to AP success"
    tet_infoline "Suspending..."
    #    WHEN=`date +'%F %T' -d '+ 5minutes'`
    echo 0 > /sys/class/rtc/rtc0/wakealarm
    #    echo "$WHEN" > /sys/class/rtc/rtc0/wakealarm
    echo "+200" > /sys/class/rtc/rtc0/wakealarm
    echo -n disk > /sys/power/state
    sleep 10
    #    iwl_load_module
    tet_infoline "Resumed"
    iwl_test || { iwl_fail; break; }
    tet_infoline "Associate to AP success"
    tpresult
}
PMSUS4()
{
    tpstart "Suspend to RAM--IBSS"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Associate to IBSS success"
    tet_infoline "Suspending..."
    #       WHEN=`date +'%F %T' -d '+ 1minutes'`
    echo 0 > /sys/class/rtc/rtc0/wakealarm
    #       echo "$WHEN" > /sys/class/rtc/rtc0/wakealarm
    echo "+50" > /sys/class/rtc/rtc0/wakealarm
    echo -n mem > /sys/power/state
    sleep 10
    #    iwl_load_module
    tet_infoline "Resumed"
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Associate to IBSS success"
    tpresult
}

PMSUS5()
{
    tpstart "Suspend to Disk--IBSS"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Associate to IBSS success"
    tet_infoline "Suspending..."
    #    WHEN=`date +'%F %T' -d '+ 5minutes'`
    echo 0 > /sys/class/rtc/rtc0/wakealarm
    #    echo "$WHEN" > /sys/class/rtc/rtc0/wakealarm
    echo "+200" > /sys/class/rtc/rtc0/wakealarm
    echo -n disk > /sys/power/state
    sleep 10
    #    iwl_load_module
    tet_infoline "Resumed"
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Associate to IBSS success"
    tpresult
}

PMPSP1()
{
    tpstart "Power Save Mode--BSS"
    iwl_load_module
    iwl_test || { iwl_fail; break; }
    tet_infoline "Associate to BSS success"
    cd /sys/class/net/wlan0/device
    i=1
    while [ $i -le 5 ]
    do
        echo $i > power_level
        cat power_level | grep "USER:$i"
        if [ $? -ne 0 ]; then
            tet_infoline "cant set power_level"
            return 1
        fi
        iwl_check ${iwl_peer[1]} || { iwl_fail; break; }
        tet_infoline "Set power_level to $i success"
        i=$((i+1))
    done
    tpresult
}

PMPSP2()
{
    tpstart "Power Save Mode--IBSS"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Associate to IBSS success"
    cd /sys/class/net/wlan0/device
    i=1
    while [ $i -le 5 ]
    do
        echo $i > power_level
        cat power_level | grep "USER:$i"
        if [ $? -ne 0 ]; then
            tet_infoline "cant set power_level"
            return 1
        fi
        iwl_check ${iwl_peer[1]} || { iwl_fail; break; }
        tet_infoline "Set power_level to $i success"
        i=$((i+1))
    done
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
