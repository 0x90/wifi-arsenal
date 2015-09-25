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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic8 ic10 ic11 ic12 ic13 ic14 ic15 ic16 ic17 ic19 ic20 ic21 ic22 ic23 ic24 ic25 ic26"
ic1="WEPBSS1"
ic2="WEPBSS2"
ic3="WEPBSS3"
ic4="WEPBSS4"
ic5="WEPBSS5"
ic6="WEPBSS6"
ic8="WEPBSS8_9"
ic10="WEPBSS10"
ic12="WEPBSS12"
ic13="WEPBSS13"
ic14="WEPBSS14"
ic15="WEPBSS15"
ic16="WEPBSS16"
ic17="WEPBSS17"
ic19="WEPIBSS1"
ic20="WEPIBSS2"
ic21="WEPIBSS3"
ic22="WEPIBSS4"
ic23="WEPIBSS5"
ic24="WEPIBSS6"
ic25="WEPIBSS1"
ic26="WEPIBSS2"

#==============
# WEP1 64bit KEY (KEY1)
WEPBSS1()
{
    tpstart "BSS Open WEP40"
    iwl_load_module
    iwl_test -a open -b enable -w enable -k 1 || { iwl_fail; break; }
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
# replace with wpa040600
#WEPBSS3()
#{
#    tpstart "BSS Shared WEP40"
#    iwl_ssh $iwl_apset_cmd --reboot || return 1
#    iwl_load_module
#    iwl_test -w enable -k 1 -a shared || { iwl_fail; break; }
#    tpresult
#}
#replace with wpa040500
#WEPBSS4()
#{
#    tpstart "BSS Shared WEP104"
#    iwl_ssh $iwl_apset_cmd --reboot || return 1
#    iwl_load_module
#    iwl_test -w enable -k 3 -a shared || { iwl_fail; break; }
#    tpresult
#}

WEPBSS5()
{
    tpstart "BSS Shared hidden-AP"
    iwl_ssh $iwl_apset_cmd --reboot || return 1
    iwl_load_module
    iwl_test -w enable -k 4 -a shared -b disable || { iwl_fail; break; }
    tpresult
}

WEPBSS6()
{
    tpstart "BSS Open hidden-AP"
    iwl_load_module
    iwl_test -w enable -k 2 -a open -b disable || { iwl_fail; break; }
    tpresult
}

WEPBSS8_9()
{
    tpstart "WEP40,WEP104--KEYIDX"
    iwl_load_module
    for i in 1 2 3 4
    do
        iwconfig wlan0 key [$i] ${iwl_keyvalue[$i]}
    done
    for i in 1 2 3 4
    do
        iwl_apset -k $i
        ifconfig wlan0 down
        iwconfig wlan0 key [$i]
        iwconfig wlan0 |grep ${iwl_displaykey[$i]} - || { iwl_fail; break; }
        tet_infoline "iwconfig wlan0 key [$i] success"
        ifconfig wlan0 up
        iwconfig wlan0 essid $iwl_essid channel $iwl_channel
        ifconfig wlan0 ${iwl_host[1]}
        sleep 5 # Long enough?
        ping -c 5 -I wlan0 ${iwl_host[1]} || { iwl_fail; break; }
        tet_infoline "Associate to $iwl_essid success"
    done
    tpresult
}

    
WEPBSS10()
{
    tpstart "WEP string key"
    iwl_load_module
    iwl_apset -e 64 -1 "6161616161" 
    ifconfig wlan0 down
    iwconfig wlan0 key s:aaaaa
    iwconfig wlan0 |grep "6161-6161-61" - || { iwl_fail; break; }
    tet_infoline "iwconfig wlan0 key s:aaaaa success"
    ifconfig wlan0 up
    iwconfig wlan0 essid $iwl_essid channel $iwl_channel
    ifconfig wlan0 ${iwl_host[1]}
    sleep 5 # Long enough?
    ping -c 5 -I wlan0 ${iwl_host[1]} || { iwl_fail; break; }
    tet_infoline "Associate to $iwl_essid success"
    tpresult
}

WEPBSS12()
{
    tpstart "BSS SSID WEP104"
    iwl_load_module
    for s in A linus 9 _ aaaaaaa11111111-----AAAAAAAAA1a_
    do
        iwl_test -s $s -w enable -k 3 && iwl_apset -n $s
        [ $? -ne 0 ] && { iwl_fail; break; }
        tet_infoline "Associate to AP $s success"
    done
    tpresult
}

WEPBSS13()
{
    tpstart "BSS SSIDs WEP40"
    iwl_load_module
    for s in A linus 9 _ aaaaaaa11111111-----AAAAAAAAA1a_
    do
        iwl_test -s $s -w enable -k 1 && iwl_apset -n $s
        [ $? -ne 0 ] && { iwl_fail; break; }
        tet_infoline "Associate to AP $s success"
    done
    tpresult
}

WEPBSS14()
{
    tpstart "BSS Channel WEP40"
    iwl_load_module
    for i in ${iwl_chans[@]}
    do
        iwl_test  -c $i -w enable -k 2
        [ $? -ne 0 ] && { iwl_fail; break; }
        tet_infoline "Associate to AP with channel $i success"
    done
    tpresult
}

WEPBSS15()
{
    tpstart "BSS Channel WEP104"
    tpstart "BSS WEP104 all channels"
    iwl_load_module
    for i in ${iwl_chans[@]}
    do
        iwl_test  -c $i -w enable -k 4
        [ $? -ne 0 ] && { iwl_fail; break; }
        tet_infoline "Associate to AP with channel $i success"
    done
    tpresult
}

WEPBSS16()
{
    tpstart "Changing key on AP and Laptops and reassociation--open mode"
    iwl_load_module
    iwl_test -w enable -k 1 -a open || { iwl_fail; break; }
    tet_infoline "Associate in open mode success"
    iwl_test -e 64 -1 "1234567890" || { iwl_fail; break; }
    tet_infoline "Associate in open mode success again"
    tpresult
}

WEPBSS17()
{
    tpstart "Changing key on AP and Laptops and reassociation--shared mode"
    iwl_load_module
    iwl_test -w enable -k 1 -a shared || { iwl_fail; break; }
    tet_infoline "Associate in shared  mode success"
    iwl_test -e 64 -1 "1234567890" -a shared || { iwl_fail; break; }
    tet_infoline "Associate in shared  mode success again"
    tpresult
}

#WEP15 Connect with key to open AP

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

WEPIBSS1_CELL()
{
    tpstart "IBSS WEP40"
    iwl_load_module
    iwl_test_ibss_cell -w enable -k 2 || { iwl_fail; break; }
    tpresult
}


WEPIBSS2_CELL()
{
    tpstart "IBSS WEP104"
    iwl_load_module
    iwl_test_ibss_cell -w enable -k 3 || { iwl_fail; break; }
    tpresult
}

WEPIBSS3()
{
    tpstart "IBSS--SSID--WEP40"
    iwl_load_module
    for i in A linus 9 _ aaaaaaa11111111-----AAAAAAAAA1a_
    do
        iwl_ibss_ap -s $i -w enable -k 1 -i && iwl_connect -s $i -w enable -k 1 -i && iwl_check ${iwl_peer[1]}
        [ $? -ne 0 ] && { iwl_fail; break; }
        tet_infoline "Associate to IBSS $i success"
    done
    tpresult

}

WEPIBSS4()
{
    tpstart "IBSS--SSID--WEP104"
    iwl_load_module
    for i in A linus 9 _ aaaaaaa11111111-----AAAAAAAAA1a_
    do
        iwl_ibss_ap -s $i -w enable -k 3 -i && iwl_connect -s $i -w enable -k 3 -i && iwl_check ${iwl_peer[1]}
        [ $? -ne 0 ] && { iwl_fail; break; }
        tet_infoline "Associate to IBSS $i success"
    done
    tpresult
}

WEPIBSS5()
{
    tpstart "IBSS--Channle--WEP40"
    iwl_load_module
    for i in ${iwl_chans[@]}
    do
        iwl_test_ibss -c $i -w enable -k 2 || { iwl_fail; break; }
        tet_infoline "Associate to IBSS with channel $i success"
    done
    tpresult
}

WEPIBSS6()
{
    tpstart "IBSS--Channel--WEP104"
    iwl_load_module
    for i in ${iwl_chans[@]}
    do
        iwl_test_ibss -c $i -w enable -k 3 || { iwl_fail; break; }
        tet_infoline "Associate to IBSS with channel $i success"
    done
    tpresult

}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
