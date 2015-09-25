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

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8"
ic1="fragbss1"
ic2="fragbss2"
ic3="fragbss3"
ic4="fragbss4"
ic5="fragibss1"
ic6="fragibss2"
ic7="fragibss3"
ic8="fragibss4"

#==============
# iwl_param_set <param> <value> <param+value in iwconfig results>
iwl_param_set()
{
    iwconfig wlan0 $1 $2
    sleep 1
    iwconfig wlan0 |grep "$3" - || return 1
    tet_infoline "iwconfig wlan0 $1 $2 success"
}

# Check_frag <peer ip>
# Ping peer with different fragment size
check_frag()
{
    local j
    local peer=$1
    for j in 500 1000 1472
    do
        ping -c 3 -I wlan0 -s $j $peer|| return 1
    done
    iwl_param_set frag off "Fragment thr:off" || return 1
    tet_infoline "Check frag success"
}

check_rts()
{
    local j
    local peer=$1
    for j in 500 1000 1472
    do
        ping -c 3 -I wlan0 -s $j $peer|| return 1
    done
    #[ $j -eq 1000 ] || break;
    iwl_param_set rts off "RTS thr:off"|| return 1
    tet_infoline "Check rts success"
}

fragbss1()
{
    local k
    tpstart "Fragementation Basic"
    iwl_load_module
    for k in 256 500 1000
    do
       iwl_test_bss -f $k || { iwl_fail; tpresult;}
       tet_infoline "Associate to AP with frag=$k"
       iwl_param_set frag $k "Fragment thr=$k" || return 1
       check_frag ${iwl_srv[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

fragbss2()
{
    local k
    tpstart "Fragmentation WEP40"
    iwl_load_module
    for k in 256 500 1000
    do
        iwl_test_bss -f $k -w enable -k 2|| { iwl_fail; tpresult; }
        iwl_param_set frag $k "Fragment thr=$k"|| returen 1
        check_frag ${iwl_srv[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

fragbss3()
{
    local k
    tpstart "Fragmentation with RTS/CTS"
    iwl_load_module
    iwl_test_bss || { iwl_fail; tpresult; }
    for k in 256 500 1000
    do 
        iwl_param_set rts $k "RTS thr=$k" || return 1    
        iwl_param_set frag $k "Fragment thr=$k"|| returen 1
        check_rts ${iwl_srv[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

fragbss4()
{
    local k
    tpstart "Fragmentation threshold"
    iwl_load_module
    for k in 256 500 1000
    do
        iwl_test_bss -f $k || { iwl_fail; tpresult; }
        check_frag ${iwl_srv[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

fragibss1()
{
    local k
    tpstart "Fragmentation IBSS basic"
    iwl_load_module
    for k in 256 500 1000
    do
        iwl_test_ibss -f $k || { iwl_fail; tpresult; }
        iwl_param_set frag $k "Fragment thr=$k"|| returen 1
        check_frag ${iwl_peer[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

fragibss2()
{
    local k
    tpstart "Fragmentation IBSS WEP40"
    iwl_load_module
    for k in 256 500 1000
    do
        iwl_test_ibss -f $k -w enable -k 2|| { iwl_fail; tpresult; }
        iwl_param_set frag $k "Fragment thr=$k"|| returen 1
        check_frag ${iwl_peer[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

fragibss3()
{
    local k
    tpstart "Fragmentation IBSS RTS/CTS"
    iwl_load_module
    for k in 256 500 1000
    do
        iwl_test_ibss || { iwl_fail; tpresult; }
        iwl_param_set frag $k "Fragment thr=$k"|| returen 1
        iwl_param_set rts $k "RTS thr=$k" || return 1
        check_rts ${iwl_peer[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

fragibss4()
{
    local k
    tpstart "Fragmentation IBSS WEP40 RTS/CTS"
    iwl_load_module
    for k in 256 500 1000
    do
        iwl_test_ibss -w enable -k 2|| { iwl_fail; tpresult; }
        iwl_param_set frag $k "Fragment thr=$k"|| returen 1
        iwl_param_set rts $k "RTS thr=$k" || return 1
        check_rts ${iwl_peer[1]} || { iwl_fail; tpresult; }
    done
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
