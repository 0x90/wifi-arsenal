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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8"
ic1="data1"
ic2="data2"
ic3="data3"
ic4="data4"
ic5="data5"
ic6="data6"
ic7="data7"
ic8="data8"


# data <bss> <wep> <frag>
data()
{    
    local str=""
    tet_infoline "Test big file (2GB) transfer under BSS=$1 WEP=$2 Frag=$3"
    iwl_load_module
    [ $2 -eq 1 ] && str="$str -w enable -k 3"
    [ $3 -eq 1 ] && str="$str -f 1000"
    if [ $1 -eq 1 ]; then
    iwl_apset $str || return $?
    iwl_bss_peer $str && iwl_connect $str && iwl_ping ${iwl_peer[1]} \
        && iwl_scp_copy ${iwl_peer[1]} /tmp/2G
    else
        essid=${iwl_host[0]}-ibss
        iwl_ibss_ap -s $essid $str -i && iwl_connect -s $essid $str -i && \
        iwl_ping ${iwl_peer[1]} && iwl_scp_copy ${iwl_peer[1]} /tmp/2G
    fi
    return $?
}

data1()
{
    tpstart "BSS WEP104 NoFrag"
    data 1 1 0 || iwl_fail
    tpresult
}

data2()
{
    tpstart "BSS NoWEP NoFrag"
    data 1 0 0 || iwl_fail
    tpresult
}

data3()
{
    tpstart "BSS WEP104 Frag1000"
    data 1 1 1 || iwl_fail
    tpresult
}

data4()
{
    tpstart "BSS NoWEP Frag1000"
    data 1 0 1 || iwl_fail
    tpresult
}

data5()
{
    tpstart "IBSS WEP104 NoFrag"
    data 0 1 0|| iwl_fail
    tpresult
}

data6()
{
    tpstart "IBSS NoWEP NoFrag"
    data 0 0 0|| iwl_fail
    tpresult
}

data7()
{
    tpstart "IBSS WEP104 NoFrag"
    data 0 1 1|| iwl_fail
    tpresult
}

data8()
{
    tpstart "IBSS NoWEP Frag1000"
    data 0 0 1|| iwl_fail
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
