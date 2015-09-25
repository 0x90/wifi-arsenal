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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14 ic15 ic16 ic17 ic18 ic19 ic20 ic21"
ic1="wpa040000"
ic2="wpa040300"
ic3="wpa040400"
ic4="wpa111100"
ic5="wpa111200"
ic6="wpa111300"
ic7="wpa111400"
ic8="wpa112100"
ic9="wpa112200"
ic10="wpa112300"
ic11="wpa112400"
ic12="wpa211100"
ic13="wpa211200"
ic14="wpa211300"
ic15="wpa211400"
ic16="wpa212100"
ic17="wpa212200"
ic18="wpa212300"
ic19="wpa212400"
ic20="wpa040500"
ic21="wpa040600"

wpa040000()
{
    tpstart "NONE"
    wpa2 0 4 0 0 0 0
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

wpa111100()
{
    tpstart "WPA-WPA-PSK-CCMP-CCMP"
    wpa2 1 1 1 1 0 0
}

wpa111200()
{
    tpstart "WPA-WPA-PSK-CCMP-TKIP"
    wpa2 1 1 1 2 0 0
}

wpa111300()
{
    tpstart "WPA-WPA-PSK-CCMP-WEP104"
    wpa2 1 1 1 3 0 0
}

wpa111400()
{
    tpstart "WPA-WPA-PSK-CCMP-WEP40"
    wpa2 1 1 1 4 0 0
}

wpa112100()
{
    tpstart "WPA-WPA-PSK-TKIP-CCMP"
    wpa2 1 1 2 1 0 0
}

wpa112200()
{
    tpstart "WPA-WPA-PSK-TKIP-TKIP"
    wpa2 1 1 2 2 0 0
}

wpa112300()
{
    tpstart "WPA-WPA-PSK-TKIP-WEP104"
    wpa2 1 1 2 3 0 0
}

wpa112400()
{
    tpstart "WPA-WPA-PSK-TKIP-WEP40"
    wpa2 1 1 2 4 0 0
}

wpa211100()
{
    tpstart "WPA2-WPA-PSK-CCMP-CCMP"
    wpa2 2 1 1 1 0 0
}

wpa211200()
{
    tpstart "WPA2-WPA-PSK-CCMP-TKIP"
    wpa2 2 1 1 2 0 0
}

wpa211300()
{
    tpstart "WPA2-WPA-PSK-CCMP-WEP104"
    wpa2 2 1 1 3 0 0
}

wpa211400()
{
    tpstart "WPA2-WPA-PSK-CCMP-WEP40"
    wpa2 2 1 1 4 0 0
}

wpa212100()
{
    tpstart "WPA2-WPA-PSK-TKIP-CCMP"
    wpa2 2 1 2 1 0 0
}

wpa212200()
{
    tpstart "WPA2-WPA-PSK-TKIP-TKIP"
    wpa2 2 1 2 2 0 0
}

wpa212300()
{
    tpstart "WPA2-WPA-PSK-TKIP-WEP104"
    wpa2 2 1 2 3 0 0
}

wpa212400()
{
    tpstart "WPA2-WPA-PSK-TKIP-WEP40"
    wpa2 2 1 2 4 0 0
}

. iwl_wpacommon.sh
. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
