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

iclist="ic1"
ic1="BSS1"


BSS1()
{
    tpstart "Broadcast AP"
    iwl_load_module
    iwl_test -a open -b enable
iwconfig 
    tpresult
}

. iwl_common.sh
# hwsim cannot ping/scp, so just return
iwl_check()
{
    return 0
}
# Run on local machine for hwsim
iwl_ssh()
{
    . $@
}

cleanup() # clean-up function()
{
    tet_infoline "Inside cleanup..."
    pkill -9 hostapd
}

. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
