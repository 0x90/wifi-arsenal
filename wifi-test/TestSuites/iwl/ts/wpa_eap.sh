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
ic1="wpa121110"
ic2="wpa121121"
ic3="wpa121122"
ic4="wpa121123"
ic5="wpa121124"
ic6="wpa121125"
ic7="wpa121131"
ic8="wpa121132"
ic9="wpa121133"
ic10="wpa121134"
ic11="wpa121135"
ic12="wpa122210"
ic13="wpa122221"
ic14="wpa122222"
ic15="wpa122223"
ic16="wpa122224"
ic17="wpa122225"
ic18="wpa122231"
ic19="wpa122232"
ic20="wpa122233"
ic21="wpa122234"
ic22="wpa122235"
ic23="wpa121310"
ic24="wpa121321"
ic25="wpa121322"
ic26="wpa121323"
ic27="wpa121324"
ic28="wpa121325"
ic29="wpa121331"
ic30="wpa121332"
ic31="wpa121333"
ic32="wpa121334"
ic33="wpa121335"
ic34="wpa122410"
ic35="wpa122421"
ic36="wpa122422"
ic37="wpa122423"
ic38="wpa122424"
ic39="wpa122425"
ic40="wpa122431"
ic41="wpa122432"
ic42="wpa122433"
ic43="wpa122434"
ic44="wpa122435"

wpa121110()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-TLS"
    wpa2 1 2 1 1 1 0
}

wpa121121()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-PEAP-MD5"
    wpa2 1 2 1 1 2 1
}

wpa121122()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-PEAP-MSCHAPV2"
    wpa2 1 2 1 1 2 2
}

wpa121123()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-PEAP-PAP"
    wpa2 1 2 1 1 2 3
}

wpa121124()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-PEAP-CHAP"
    wpa2 1 2 1 1 2 4
}

wpa121125()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-PEAP-MSCHAP"
    wpa2 1 2 1 1 2 5
}

wpa121131()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-TTLS-MD5"
    wpa2 1 2 1 1 3 1
}

wpa121132()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-TTLS-MSCHAPV2"
    wpa2 1 2 1 1 3 2
}

wpa121133()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-TTLS-PAP"
    wpa2 1 2 1 1 3 3
}

wpa121134()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-TTLS-CHAP"
    wpa2 1 2 1 1 3 4
}

wpa121135()
{
    tpstart "WPA-WPA-EAP-CCMP-CCMP-TTLS-MSCHAP"
    wpa2 1 2 1 1 3 5
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

wpa122222()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-PEAP-MSCHAPV2"
    wpa2 1 2 2 2 2 2
}

wpa122223()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-PEAP-PAP"
    wpa2 1 2 2 2 2 3
}

wpa122224()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-PEAP-CHAP"
    wpa2 1 2 2 2 2 4
}

wpa122225()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-PEAP-MSCHAP"
    wpa2 1 2 2 2 2 5
}

wpa122231()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-TTLS-MD5"
    wpa2 1 2 2 2 3 1
}

wpa122232()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-TTLS-MSCHAPV2"
    wpa2 1 2 2 2 3 2
}

wpa122233()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-TTLS-PAP"
    wpa2 1 2 2 2 3 3
}

wpa122234()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-TTLS-CHAP"
    wpa2 1 2 2 2 3 4
}

wpa122235()
{
    tpstart "WPA-WPA-EAP-TKIP-TKIP-TTLS-MSCHAP"
    wpa2 1 2 2 2 3 5
}

wpa121310()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-TLS"
    wpa2 1 2 1 3 1 0
}

wpa121321()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-PEAP-MD5"
    wpa2 1 2 1 3 2 1
}

wpa121322()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-PEAP-MSCHAPV2"
    wpa2 1 2 1 3 2 2
}

wpa121323()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-PEAP-PAP"
    wpa2 1 2 1 3 2 3
}

wpa121324()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-PEAP-CHAP"
    wpa2 1 2 1 3 2 4
}

wpa121325()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-PEAP-MSCHAP"
    wpa2 1 2 1 3 2 5
}

wpa121331()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-TTLS-MD5"
    wpa2 1 2 1 3 3 1
}

wpa121332()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-TTLS-MSCHAPV2"
    wpa2 1 2 1 3 3 2
}

wpa121333()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-TTLS-PAP"
    wpa2 1 2 1 3 3 3
}

wpa121334()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-TTLS-CHAP"
    wpa2 1 2 1 3 3 4
}

wpa121335()
{
    tpstart "WPA-WPA-EAP-CCMP-WEP104-TTLS-MSCHAP"
    wpa2 1 2 1 3 3 5
}

wpa122410()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-TLS"
    wpa2 1 2 2 4 1 0
}

wpa122421()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-PEAP-MD5"
    wpa2 1 2 2 4 2 1
}

wpa122422()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-PEAP-MSCHAPV2"
    wpa2 1 2 2 4 2 2
}

wpa122423()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-PEAP-PAP"
    wpa2 1 2 2 4 2 3
}

wpa122424()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-PEAP-CHAP"
    wpa2 1 2 2 4 2 4
}

wpa122425()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-PEAP-MSCHAP"
    wpa2 1 2 2 4 2 5
}

wpa122431()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-TTLS-MD5"
    wpa2 1 2 2 4 3 1
}

wpa122432()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-TTLS-MSCHAPV2"
    wpa2 1 2 2 4 3 2
}

wpa122433()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-TTLS-PAP"
    wpa2 1 2 2 4 3 3
}

wpa122434()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-TTLS-CHAP"
    wpa2 1 2 2 4 3 4
}

wpa122435()
{
    tpstart "WPA-WPA-EAP-TKIP-WEP40-TTLS-MSCHAP"
    wpa2 1 2 2 4 3 5
}

. iwl_wpacommon.sh
. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
