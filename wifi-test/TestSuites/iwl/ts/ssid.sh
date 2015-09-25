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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12"
ic1="ssid1"
ic2="ssid2"
ic3="ssid3"
ic6="ssid6"
ic7="ssid7"
ic8="ssid8"
ic9="ssid9"
ic10="ssid10"
ic11="ssid11"
ic12="ssid12"

ssid1()
{
    tpstart "SSID Scan"
    iwl_load_module
    ifconfig wlan0 up
    iwlist wlan0 scanning | grep "Cell.*Address:" - || iwl_fail
    c=`iwlist wlan0 scanning | grep "Cell.*Address:" - |wc`
    tet_infoline "scan gets $c APs"
    [ $c -lt 6 ] && iwl_fail # Assume that there are > 6 APs
    tpresult
}

ssid2()
{
    tpstart "iwlist freq"
    iwl_load_module
    ifconfig wlan0 up
    c=`iwlist wlan0 freq | grep Channel - |wc`
    tet_infoline "The card gets $c channel"
    [ $c -lt 20 ] && iwl_fail # Assume that support +20 channel/freq
    tpresult
}

ssid3()
{
    tpstart "iwlist channel"
    iwl_load_module
    ifconfig wlan0 up
    c=`iwlist wlan0 chan | grep Channel - |wc`
    tet_infoline "The card gets $c channel"
    [ $c -lt 20 ] && iwl_fail # Assume that support +20 channel/freq
    tpresult
}

ssid6()
{
    tpstart "iwlist encr"
    iwl_load_module
    iwconfig wlan0 key 2222000000 [2]
    iwlist wlan0 encr |grep "\[2\]: 2222-0000-00" - || iwl_fail
    iwlist wlan0 encr |grep "Current .* \[2\]" - || iwl_fail
    tpresult
}

ssid7()
{
    tpstart "iwlist key"
    iwl_load_module
    iwconfig wlan0 key 2222000000 [2]
    iwlist wlan0 key |grep "\[2\]: 2222-0000-00" - || iwl_fail
    iwlist wlan0 key |grep "Current .* \[2\]" - || iwl_fail
    tpresult
}

ssid8()
{
    tpstart "iwlist power"
    iwl_load_module
    iwconfig wlan0 power off    # Will not test real work, no support
    iwlist wlan0 power|grep "Current.*off" - || iwl_fail
    tpresult
}

ssid9()
{
    tpstart "iwlist txpower"
    iwl_load_module
    iwconfig wlan0 txpower 15
    iwlist wlan0 txpower |grep "Current.*15" -|| iwl_fail
    tpresult
}

ssid10()
{
    tpstart "iwlist retry"
    iwl_load_module
    iwconfig wlan0 retry 5
    iwlist wlan0 retry |grep "limit:5" -|| iwl_fail
    tpresult
}

ssid11()
{
    tpstart "iwlist scan hidden AP"
    iwl_load_module
    iwl_apset -b disable
    ifconfig wlan0 up
    iwlist wlan0 scan |grep ESSID:\"\" - || iwl_fail
    tpresult
}

ssid12()
{
    tpstart "disable AP and scan"
    iwl_load_module
    iwl_apset &
    sleep 2       # Assume there is no such AP after 2 seconds
    iwlist wlan0 scan |grep $iwl_ap_mac - && iwl_fail
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
