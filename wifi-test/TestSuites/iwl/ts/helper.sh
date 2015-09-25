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

#set -x

tet_startup="startup1"            # startup function
tet_cleanup="cleanup"            # cleanup function

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8"
ic1="Start_A_Band"
ic2="Start_B_Band"
ic3="Start_G_Band"
ic4="Start_N_Band"
ic6="Reload_AP"
ic7="Start_N2_Band"

Start_A_Band()
{
    iwl_tpstart "Start_A_Band"
    file=$TVS_ROOT/tsets/iwl/tvs_env
    sed "s/^iwl_band=.*/iwl_band=A-ONLY/" $file > ${file}.tmp
    cp ${file}.tmp ${file}
    tpresult
}

Start_B_Band()
{
    iwl_tpstart "Start_B_Band"
    file=$TVS_ROOT/tsets/iwl/tvs_env
    sed "s/^iwl_band=.*/iwl_band=B-ONLY/" $file > ${file}.tmp
    cp ${file}.tmp ${file}
    tpresult
}

Start_G_Band()
{
    iwl_tpstart "Start_G_Band"
    file=$TVS_ROOT/tsets/iwl/tvs_env
    sed "s/^iwl_band=.*/iwl_band=G-ONLY/" $file > ${file}.tmp
    cp ${file}.tmp ${file}
    tpresult
}

Start_N_Band()
{
    iwl_tpstart "Start_N_Band"
    file=$TVS_ROOT/tsets/iwl/tvs_env
    sed "s/^iwl_band=.*/iwl_band=N-ONLY/" $file > ${file}.tmp
    cp ${file}.tmp ${file}
    tpresult
}

Start_N2_Band()
{
    iwl_tpstart "Start_N2_Band"
    file=$TVS_ROOT/tsets/iwl/tvs_env
    sed "s/^iwl_band=.*/iwl_band=N2.4-ONLY/" $file > ${file}.tmp
    cp ${file}.tmp ${file}
    tpresult
}

Reload_AP()
{
        iwl_tpstart "Reload_AP"
        iwl_ssh $iwl_apset_cmd --reboot || return 1
        sleep 120
        tpresult
}

startup1() # start-up function()
{
    tet_infoline "Inside startup..."
    mkdir -p $TMPDIR
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

set -x
# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
