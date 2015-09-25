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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13"
ic1="BSS1"
ic2="BSS2"
ic3="WEPBSS1"
ic4="WEPBSS2"
ic5="WEPBSS3"
ic6="WEPBSS4"
ic7="BSSDATA1"
ic8="BSSCHAN1"
ic9="IBSS1"
ic10="WEPIBSS1"
ic11="WEPIBSS2"
ic12="fragbss1"
ic13="fragibss1"
ic14="wpa112200"
ic15="wpa211100"
ic16="wpa030310"
ic17="wpa040300"
ic18="wpa040400"
ic19="wpa040500"
ic20="wpa040600"
ic21="wpa030421"
ic22="wpa122210"
ic23="wpa122221"
ic24="wpa122232"
ic25="wpa221121"
ic26=IBSSCHAN1


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

# WEP1 64bit KEY (KEY1)
WEPBSS1()
{
    tpstart "BSS Open WEP40"
    iwl_load_module
    iwl_test -a open -b enable -w enable -k 1
    tpresult
}

# WEP2 128bit KEY
WEPBSS2()
{
    tpstart "BSS Open WEP104"
    iwl_load_module
    iwl_test -a open -b enable -w enable -k 3 || { iwl_fail; break; }
    tpresult
}

# WEP3 64bit Key (Shared in AP)
WEPBSS3()
{
    tpstart "BSS Shared WEP40"
    iwl_ssh $iwl_apset_cmd --reboot || return 1
    iwl_load_module
    iwl_test -w enable -k 1 -a shared || { iwl_fail; break; }
    tpresult
}

# WEP4 128 Key (Shared in AP)
WEPBSS4()
{
    tpstart "BSS Shared WEP104"
    iwl_ssh $iwl_apset_cmd --reboot || return 1
    iwl_load_module
    iwl_test -w enable -k 3 -a shared || { iwl_fail; break; }
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

# IBSS1   Configure two laptops in ad-hoc mode without WEP
IBSS1()
{
    tpstart "IBSS Unicast"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; break; }
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

WEPIBSS1()
{
    tpstart "IBSS WEP40"
    iwl_load_module
    iwl_test_ibss -w enable -k 2 || { iwl_fail; break; }
    tpresult
}


WEPIBSS2()
{
    tpstart "IBSS WEP104"
    iwl_load_module
    iwl_test_ibss -w enable -k 3 || { iwl_fail; break; }
    tpresult
}

# check_frag_rts <param> <value> <peer machine>
check_frag_rts()
{
    local j
    local peer=$3
    local phy=`iw list |grep Wiphy |awk '{print $2}'`
    iw phy $phy set $1 $2 || return 1
    for j in 500 1000 1472
    do
        ping -c 3 -I wlan0 -s $j $peer|| return 1
    done
    iw phy $phy set $1 off || return 1
    tet_infoline "Check $1 $2 success"
}

fragbss1()
{
    local k
    local peer=${iwl_srv[1]}
    tpstart "Fragementation Basic"
    iwl_load_module
    iwl_test_bss || { iwl_fail; tpresult;}
    tet_infoline "Associated to AP"
    for k in 256 500 1000
    do
	tet_infoline "Associating to AP with frag=$k"
	check_frag_rts frag $k $peer|| { iwl_fail "Check frag $k failed"; }
	tet_infoline "Success"
    done
    tpresult
}

fragibss1()
{
    local k
    local peer=${iwl_peer[1]}
    tpstart "Fragmentation IBSS basic"
    iwl_load_module
    iwl_test_ibss || { iwl_fail; tpresult; }
    for k in 256 500 1000
    do
	tet_infoline "Associating to cell with frag=$k"
	check_frag_rts frag $k $peer|| { iwl_fail "Check frag $k failed"; }
	tet_infoline "Success"
    done
    tpresult
}

wpa112200()
{
    tpstart "WPA-WPA-PSK-TKIP-TKIP"
    wpa2 1 1 2 2 0 0
}

wpa211100()
{
    tpstart "WPA2-WPA-PSK-CCMP-CCMP"
    wpa2 2 1 1 1 0 0
}

wpa030310()
{
    tpstart "IEEE8021X-WEP104-TLS"
    wpa2 0 3 0 3 1 0
}

wpa040300()
{
    tpstart "NONE-WEP104"
    wpa2 0 4 0 3 0 0
}

wpa040400()
{
    tpstart "NONE-WEP40"
    wpa2 0 4 0 4 0 0
}

wpa040500()
{
       tpstart "Shared-WEP104"
       wpa2 0 4 0 5 0 0
}

wpa040600()
{
       tpstart "Shared-WEP40"
       wpa2 0 4 0 6 0 0
}

wpa030421()
{
    tpstart "IEEE8021X-WEP40-PEAP-MD5"
    wpa2 0 3 0 4 2 1
}

wpa122210()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-TLS"
    wpa2 1 2 2 2 1 0
}

wpa122221()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-PEAP-MD5"
    wpa2 1 2 2 2 2 1
}

wpa122232()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-TTLS-MSCHAPV2"
    wpa2 1 2 2 2 3 2
}

wpa221121()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-PEAP-MD5"
    wpa2 2 2 1 1 2 1
}

. iwl_wpacommon.sh
. iwl_iw.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
