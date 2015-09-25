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

tet_startup="startup"			# startup function
tet_cleanup="cleanup"			# cleanup function
iclist="ic1 ic2 ic4 ic5 ic6 ic7 ic8"
ic1="BSS1"
ic2="BSS2"
ic3="BSS5"
ic4="BSSDATA1"
ic5="BSSDATA2"
ic6="BSSSSID1"
ic7="BSSCHAN1"
ic8="BSS11NCHAN1"

#==============
BSS1()
{
    tpstart "Broadcast AP"
    iwl_load_module
    iwl_test -a open -b enable
    tpresult
}

BSS2()
{
    tpstart "Hidden AP"
    iwl_load_module
    iwl_test -a open -b disable
    tpresult
}

BSS5()
{	
    local pid
    tpstart "Get IP through DHCP"
    iwl_load_module
    iwl_test -d 
    # Kill dhclient that launched in iwl_connect()
    pid=`ps -ef |grep dhclient |grep wlan0 |awk '{print $2}'`
    kill -9 $pid
    tpresult
}

# BSSDATA1        Send Unicast package to another wireless achine
BSSDATA1()
{
    tpstart "BSS unicast"
    iwl_load_module
    iwl_test_peer
    tpresult
}

# BSSDATA2        Send Broadcast package to the network
BSSDATA2()
{
    tpstart "BSS broadcast"
    iwl_load_module
    iwl_test_peer
    msg=`ping -b 192.168.50.255 -c 10`
    "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
    ssh ${iwl_peer[0]} "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
    echo $msg |grep $iwl_wap - || iwl_fail
    echo $msg |grep $iwl_wpeer - || iwl_fail
    tpresult
}

#BSSSSID1 different names of SSID
BSSSSID1()
{
    tpstart "BSS SSIDs"
    iwl_load_module
    for i in A linus 9 _ aaaaaaa11111111-----AAAAAAAAA1a_
    do
	tet_infoline "Associating to essid $i success"
	iwl_test -s $s && iwl_apset -n $s 
	tet_infoline "Success"
    done
    tpresult
}


BSSCHAN1()
{
    tpstart "BSS all channels"
    iwl_load_module
    for i in ${iwl_chans[@]}
    do
	tet_infoline "Associating with channel $i"
	iwl_test  -c $i
	tet_infoline "Success"
    done
    tpresult
}

BSS11NCHAN1()
{
    tpstart "BSS fat channel"
    iwl_load_module
    for i in ${iwl_chans[@]}
    do
	tet_infoline "Associating with fat channel $i above"
        iwl_test -c $i -h 40-above
	tet_infoline "Success"
	tet_infoline "Associating with fat channel $i below"
	iwl_test  -h 40-below
	tet_infoline "Success"
    done
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
