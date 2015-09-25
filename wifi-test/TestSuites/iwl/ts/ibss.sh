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

iclist="ic1 ic3 ic5 ic6 ic7 ic8 ic9 ic10 ic11"
ic1="IBSS1"
ic3="IBSS3"
ic5="IBSSCHAN1"
ic6="IBSSDATA1"
ic7="IBSSSSID1"
ic8="BSS3"
ic9="BSS4"
ic10="IBSS1_CELL"
ic11="IBSSCHAN1_CELL"

#=====================
# IBSS1   Configure two laptops in ad-hoc mode without WEP
IBSS1()
{
    tpstart "IBSS Unicast"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    tpresult
}

IBSS3()
{
    tpstart "IBSS reconnet after reload"
    iwl_load_module
    iwl_test_ibss || iwl_fail
    essid=${iwl_host[0]}-ibss # Refer to iwl_test_ibss
    tet_infoline "Reload driver and reassociate"
    iwl_load_module
    iwl_connect -s $essid -i && iwl_check ${iwl_peer[1]}
    [ $? -eq 0 ] || iwl_fail 
    tpresult
}

IBSSCHAN1()
{
    tpstart "IBSS all channel"
    #iwl_load_module
    for i in ${iwl_chans[@]}
    do
        iwl_load_module
        # workaround for ibss channel
        ssh ${iwl_peer[0]} "modprobe -r iwl4965"
        iwl_test_ibss -c $i || { iwl_fail; break; }
        tet_infoline "Associate to IBSS cell with channel $i success"
    done
    tpresult
}

IBSS1_CELL()
{
    tpstart "IBSS Unicast"
    iwl_load_module
    iwl_test_ibss_cell || { iwl_fail; break; }
    tpresult
}

IBSSCHAN1_CELL()
{
    tpstart "IBSS all channel"
    #iwl_load_module
    for i in ${iwl_chans[@]}
    do
        iwl_load_module
        # workaround for ibss channel
        ssh ${iwl_peer[0]} "modprobe -r iwl4965"
        iwl_test_ibss_cell -c $i || { iwl_fail; break; }
        tet_infoline "Associate to IBSS cell with channel $i success"
    done
    tpresult
}

IBSSDATA1()
{
    tpstart "IBSS broadcast"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
    ssh ${iwl_peer[0]} "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
    msg=`ping -b 192.168.50.255 -c3`
    echo $msg |grep $iwl_wpeer - || iwl_fail
    tpresult
}


IBSSSSID1()
{
    tpstart "SSID in IBSS probe response"
    iwl_load_module
    for i in A linus 9 _ aaaaaaa11111111-----AAAAAAAAA1a_
    do
        iwl_ibss_ap -s $i -i && iwl_connect -s $i -i && iwl_check ${iwl_peer[1]}
        [ $? -ne 0 ] && { iwl_fail; break; }
        tet_infoline "Associate to IBSS cell with essid $i success"
    done
    tpresult
}

BSS3()
{
    tpstart "BSS and IBSS can not commnuicate"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Associate to IBSS cell success"
    essid=${iwl_host[0]}-ibss # Refer to iwl_test_ibss
    iwl_load_module
    iwl_test -s $essid && iwl_apset -n $essid
    [ $? -ne 0 ] && { iwl_fail; break; }
    tet_infoline "Associate to BSS AP success"
    ping -c 3 ${iwl_peer[1]} && { iwl_fail; break; } # Should not connect
    tet_infoline "Cannot ping to IBSS cell in peer machine"
    tpresult
}

BSS4()
{
    tpstart "DUT is able to connect to AP and to IBSS network"
    iwl_load_module
    iwl_test || { iwl_fail; break; }
    tet_infoline "Associate to BSS AP success"
    iwl_test_ibss || { iwl_fail; break; }
    tet_infoline "Associate to IBSS cell success"
    tpresult

}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
