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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14 ic15 ic16 ic17 ic18 ic19 ic20 ic21 ic22"


ic1="wpa030310"
ic2="wpa030321"
ic3="wpa030322"
ic4="wpa030323"
ic5="wpa030324"
ic6="wpa030325"
ic7="wpa030331"
ic8="wpa030332"
ic9="wpa030333"
ic10="wpa030334"
ic11="wpa030335"
ic12="wpa030410"
ic13="wpa030421"
ic14="wpa030422"
ic15="wpa030423"
ic16="wpa030424"
ic17="wpa030425"
ic18="wpa030431"
ic19="wpa030432"
ic20="wpa030433"
ic21="wpa030434"
ic22="wpa030435"
wpa030310()
{
    tpstart "IEEE8021X-WEP104-TLS"
    wpa2 0 3 0 3 1 0
}

wpa030321()
{
    tpstart "IEEE8021X-WEP104-PEAP-MD5"
    wpa2 0 3 0 3 2 1
}

wpa030322()
{
    tpstart "IEEE8021X-WEP104-PEAP-MSCHAPV2"
    wpa2 0 3 0 3 2 2
}

wpa030323()
{
    tpstart "IEEE8021X-WEP104-PEAP-PAP"
    wpa2 0 3 0 3 2 3
}

wpa030324()
{
    tpstart "IEEE8021X-WEP104-PEAP-CHAP"
    wpa2 0 3 0 3 2 4
}

wpa030325()
{
    tpstart "IEEE8021X-WEP104-PEAP-MSCHAP"
    wpa2 0 3 0 3 2 5
}

wpa030331()
{
    tpstart "IEEE8021X-WEP104-TTLS-MD5"
    wpa2 0 3 0 3 3 1
}

wpa030332()
{
    tpstart "IEEE8021X-WEP104-TTLS-MSCHAPV2"
    wpa2 0 3 0 3 3 2
}

wpa030333()
{
    tpstart "IEEE8021X-WEP104-TTLS-PAP"
    wpa2 0 3 0 3 3 3
}

wpa030334()
{
    tpstart "IEEE8021X-WEP104-TTLS-CHAP"
    wpa2 0 3 0 3 3 4
}

wpa030335()
{
    tpstart "IEEE8021X-WEP104-TTLS-MSCHAP"
    wpa2 0 3 0 3 3 5
}

wpa030410()
{
    tpstart "IEEE8021X-WEP40-TLS"
    wpa2 0 3 0 4 1 0
}

wpa030421()
{
    tpstart "IEEE8021X-WEP40-PEAP-MD5"
    wpa2 0 3 0 4 2 1
}

wpa030422()
{
    tpstart "IEEE8021X-WEP40-PEAP-MSCHAPV2"
    wpa2 0 3 0 4 2 2
}

wpa030423()
{
    tpstart "IEEE8021X-WEP40-PEAP-PAP"
    wpa2 0 3 0 4 2 3
}

wpa030424()
{
    tpstart "IEEE8021X-WEP40-PEAP-CHAP"
    wpa2 0 3 0 4 2 4
}

wpa030425()
{
    tpstart "IEEE8021X-WEP40-PEAP-MSCHAP"
    wpa2 0 3 0 4 2 5
}

wpa030431()
{
    tpstart "IEEE8021X-WEP40-TTLS-MD5"
    wpa2 0 3 0 4 3 1
}

wpa030432()
{
    tpstart "IEEE8021X-WEP40-TTLS-MSCHAPV2"
    wpa2 0 3 0 4 3 2
}

wpa030433()
{
    tpstart "IEEE8021X-WEP40-TTLS-PAP"
    wpa2 0 3 0 4 3 3
}

wpa030434()
{
    tpstart "IEEE8021X-WEP40-TTLS-CHAP"
    wpa2 0 3 0 4 3 4
}

wpa030435()
{
    tpstart "IEEE8021X-WEP40-TTLS-MSCHAP"
    wpa2 0 3 0 4 3 5
}


. iwl_wpacommon.sh
. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
