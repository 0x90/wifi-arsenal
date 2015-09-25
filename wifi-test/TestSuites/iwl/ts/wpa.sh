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

tet_startup="startup"    		# startup function
tet_cleanup="cleanup"    		# cleanup function
iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11"
#iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14 ic15 ic16 ic17 ic18 ic19 ic20 ic21"
ic1="wpa010"
ic2="wpa020"
ic3="wpa030"
ic4="wpa040"
ic5="wpa050"
ic6="wpa060"
ic7="wpa070"
ic8="wpa080"
ic9="wpa090"
ic10="wpa110"
ic11="wpa120"
ic12="wpa190"
ic13="wpa210"
ic14="wpa270"
ic15="wpa280"
ic16="wpa220"
ic17="wpa230"
ic18="wpa240"
ic19="wpa250"
ic20="wpa290"
ic21="wpa300"

wpa010()
{
    #wpa "WPA010"  -a psk -t TKIP -x wpa/WPA_PSK_TKIP.conf
    tpstart "WPA-WPA-PSK-TKIP-TKIP"
    wpa2 1 1 2 2 0 0
}

wpa020()
{
    #wpa "WPA020" -a psk -t AES -x wpa/WPA_PSK_AES.conf
    tpstart "WPA2-WPA-PSK-CCMP-CCMP"
    wpa2 2 1 1 1 0 0
}

wpa030()
{
    #wpa "WPA030" -a wpa -x wpa/WPA_EAP_PEAP.conf
    tpstart "WPA-WPA-EAP-PEAP"
    wpa2 1 2 0 2 2 0
}

wpa040()
{
    #wpa "WPA040" -a wpa -x wpa/WPA_EAP_TLS.conf
    tpstart "WPA-WPA-EAP-TLS"
    wpa2 1 2 0 0 1 0
}

wpa050()
{
    #wpa "WPA050" -a wpa -x wpa/WPA_EAP_TTLS_PAP.conf
    tpstart "WPA-WPA-EAP-TTLS-PAP"
    wpa2 1 2 0 0 3 3
    
}

wpa060()
{
    #wpa "WPA060" -a wpa -x wpa/WPA_EAP_TTLS_MSCHAP.conf
    tpstart "WPA-WPA-EAP-TTLS-PAP"
    wpa2 1 2 0 0 3 5
}

wpa070()
{
    #wpa "WPA070" -a wpa -x wpa/WPA_EAP_TTLS_CHAP.conf
    tpstart "WPA-WPA-EAP-TTLS-PAP"
    wpa2 1 2 0 0 3 4
}

wpa080()
{
    #wpa "WPA080" -a wpa -x wpa/WPA_EAP_TTLS_MD5.conf
    tpstart "WPA-WPA-EAP-TTLS-PAP"
    wpa2 1 2 0 0 3 1
}

wpa090()
{
    #wpa "WPA090" -a wpa -x wpa/WPA_EAP_TTLS_MSCHAPV2.conf
    tpstart "WPA-WPA-EAP-TTLS-PAP"
    wpa2 1 2 0 0 3 2
}

wpa110()
{
    #wpa "WPA110" -a psk2 -t TKIP -x wpa/WPA2_PSK_TKIP.conf
    tpstart "WPA2-WPA-PSK-TKIP-TKIP"
    wpa2 2 1 2 2 0 0
}

wpa120()
{
    #wpa "WPA120" -a psk2 -t AES -x wpa/WPA2_PSK_AES.conf
    tpstart "WPA2-WPA-PSK-CCMP-CCMP"
    wpa2 2 1 1 1 0 0
}

# Need to copy big file in following cases? Rewrite iwl_test
iwl_test_bigfile()
{
    iwl_apset $@ && iwl_connect $@ && iwl_ping ${iwl_srv[1]} \
     && iwl_scp_copy ${iwl_srv[1]} /tmp/2G
    return $?
}

wpa_bf()
{
    tpname=$1
    shift
    iwl_tpstart $tpname
    iwl_load_module
    iwl_test_bigfile $@ || iwl_fail
    iwl_close_wpa
    iwl_tpresult
}

wpa190()
{
    wpa_bf "WPA190" -f 1000 -a psk -t TKIP -x wpa/WPA_PSK_TKIP.conf
}

wpa210()
{
    wpa_bf "WPA210" -a psk -t TKIP -x wpa/WPA_PSK_TKIP.conf
}

wpa270()
{
    wpa_bf "WPA270" -f 1000 -a psk -t AES -x wpa/WPA_PSK_AES.conf
}

wpa280()
{
    wpa_bf "WPA280" -a psk -t AES -x wpa/WPA_PSK_AES.conf
}

wpa220()
{
    wpa_bf "WPA220" -f 1000 -a wpa -x wpa/WPA_EAP_TLS.conf
}

wpa230()
{
    wpa_bf "WPA230" -a wpa -x wpa/WPA_EAP_TLS.conf
}

wpa240()
{
    wpa_bf "WPA240" -f 1000 -a psk2 -t TKIP -x wpa/WPA2_PSK_TKIP.conf
}

wpa250()
{
    wpa_bf "WPA250" -a psk2 -t TKIP -x wpa/WPA2_PSK_TKIP.conf
}

wpa290()
{
    wpa_bf "WPA290" -f 1000 -a psk2 -t AES -x wpa/WPA2_PSK_AES.conf
}

wpa300()
{
    wpa_bf "WPA300" -a psk2 -t AES -x wpa/WPA2_PSK_AES.conf
}

. iwl_common.sh
. iwl_wpacommon.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
