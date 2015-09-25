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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14 ic15 ic16 ic17 ic18 ic19 ic20 ic21 ic22 ic23 ic24 ic25 ic26 ic27 ic28 ic29 ic30 ic31 ic32 ic33 ic34 ic35 ic36 ic37 ic38 ic39 ic40 ic41 ic42 ic43 ic44"
ic1="wpa221110"
ic2="wpa221121"
ic3="wpa221122"
ic4="wpa221123"
ic5="wpa221124"
ic6="wpa221125"
ic7="wpa221131"
ic8="wpa221132"
ic9="wpa221133"
ic10="wpa221134"
ic11="wpa221135"
ic12="wpa222210"
ic13="wpa222221"
ic14="wpa222222"
ic15="wpa222223"
ic16="wpa222224"
ic17="wpa222225"
ic18="wpa222231"
ic19="wpa222232"
ic20="wpa222233"
ic21="wpa222234"
ic22="wpa222235"
ic23="wpa221310"
ic24="wpa221321"
ic25="wpa221322"
ic26="wpa221323"
ic27="wpa221324"
ic28="wpa221325"
ic29="wpa221331"
ic30="wpa221332"
ic31="wpa221333"
ic32="wpa221334"
ic33="wpa221335"
ic34="wpa222410"
ic35="wpa222421"
ic36="wpa222422"
ic37="wpa222423"
ic38="wpa222424"
ic39="wpa222425"
ic40="wpa222431"
ic41="wpa222432"
ic42="wpa222433"
ic43="wpa222434"
ic44="wpa222435"

wpa221110()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-TLS"
    wpa2 2 2 1 1 1 0
}

wpa221121()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-PEAP-MD5"
    wpa2 2 2 1 1 2 1
}

wpa221122()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-PEAP-MSCHAPV2"
    wpa2 2 2 1 1 2 2
}

wpa221123()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-PEAP-PAP"
    wpa2 2 2 1 1 2 3
}

wpa221124()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-PEAP-CHAP"
    wpa2 2 2 1 1 2 4
}

wpa221125()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-PEAP-MSCHAP"
    wpa2 2 2 1 1 2 5
}

wpa221131()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-TTLS-MD5"
    wpa2 2 2 1 1 3 1
}

wpa221132()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-TTLS-MSCHAPV2"
    wpa2 2 2 1 1 3 2
}

wpa221133()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-TTLS-PAP"
    wpa2 2 2 1 1 3 3
}

wpa221134()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-TTLS-CHAP"
    wpa2 2 2 1 1 3 4
}

wpa221135()
{
    tpstart "WPA2-WPA-EAP-CCMP-CCMP-TTLS-MSCHAP"
    wpa2 2 2 1 1 3 5
}

wpa222210()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-TLS"
    wpa2 2 2 2 2 1 0
}

wpa222221()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-PEAP-MD5"
    wpa2 2 2 2 2 2 1
}

wpa222222()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-PEAP-MSCHAPV2"
    wpa2 2 2 2 2 2 2
}

wpa222223()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-PEAP-PAP"
    wpa2 2 2 2 2 2 3
}

wpa222224()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-PEAP-CHAP"
    wpa2 2 2 2 2 2 4
}

wpa222225()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-PEAP-MSCHAP"
    wpa2 2 2 2 2 2 5
}

wpa222231()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-TTLS-MD5"
    wpa2 2 2 2 2 3 1
}

wpa222232()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-TTLS-MSCHAPV2"
    wpa2 2 2 2 2 3 2
}

wpa222233()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-TTLS-PAP"
    wpa2 2 2 2 2 3 3
}

wpa222234()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-TTLS-CHAP"
    wpa2 2 2 2 2 3 4
}

wpa222235()
{
    tpstart "WPA2-WPA-EAP-TKIP-TKIP-TTLS-MSCHAP"
    wpa2 2 2 2 2 3 5
}

wpa221310()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-TLS"
    wpa2 2 2 1 3 1 0
}

wpa221321()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-PEAP-MD5"
    wpa2 2 2 1 3 2 1
}

wpa221322()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-PEAP-MSCHAPV2"
    wpa2 2 2 1 3 2 2
}

wpa221323()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-PEAP-PAP"
    wpa2 2 2 1 3 2 3
}

wpa221324()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-PEAP-CHAP"
    wpa2 2 2 1 3 2 4
}

wpa221325()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-PEAP-MSCHAP"
    wpa2 2 2 1 3 2 5
}

wpa221331()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-TTLS-MD5"
    wpa2 2 2 1 3 3 1
}

wpa221332()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-TTLS-MSCHAPV2"
    wpa2 2 2 1 3 3 2
}

wpa221333()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-TTLS-PAP"
    wpa2 2 2 1 3 3 3
}

wpa221334()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-TTLS-CHAP"
    wpa2 2 2 1 3 3 4
}

wpa221335()
{
    tpstart "WPA2-WPA-EAP-CCMP-WEP104-TTLS-MSCHAP"
    wpa2 2 2 1 3 3 5
}

wpa222410()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-TLS"
    wpa2 2 2 2 4 1 0
}

wpa222421()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-PEAP-MD5"
    wpa2 2 2 2 4 2 1
}

wpa222422()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-PEAP-MSCHAPV2"
    wpa2 2 2 2 4 2 2
}

wpa222423()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-PEAP-PAP"
    wpa2 2 2 2 4 2 3
}

wpa222424()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-PEAP-CHAP"
    wpa2 2 2 2 4 2 4
}

wpa222425()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-PEAP-MSCHAP"
    wpa2 2 2 2 4 2 5
}

wpa222431()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-TTLS-MD5"
    wpa2 2 2 2 4 3 1
}

wpa222432()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-TTLS-MSCHAPV2"
    wpa2 2 2 2 4 3 2
}

wpa222433()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-TTLS-PAP"
    wpa2 2 2 2 4 3 3
}

wpa222434()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-TTLS-CHAP"
    wpa2 2 2 2 4 3 4
}

wpa222435()
{
    tpstart "WPA2-WPA-EAP-TKIP-WEP40-TTLS-MSCHAP"
    wpa2 2 2 2 4 3 5
}

. iwl_wpacommon.sh
. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
