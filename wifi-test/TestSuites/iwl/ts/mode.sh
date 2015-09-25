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
iclist="ic1 ic2 ic3"
ic1="MODE2"
ic2="MODE4"
ic3="MODE6"

#==============
MODE2()
{
    tpstart "Moving from monitor mode -> managed mode"
    iwl_load_module
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    ifconfig wlan0 up
    sleep 3
    ifconfig wlan0 down
    iwconfig wlan0 mode managed
    iwl_test 
    [ $? -ne 0 ] && { iwl_fail; break; }
    tpresult
}

MODE4()
{
    tpstart "Moving from monitor mode -> ad-hoc mode"
    iwl_load_module
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    ifconfig wlan0 up
    sleep 3
    iwl_test_ibss
    [ $? -ne 0 ] && { iwl_fail; break; }
    tpresult
}

MODE6()
{
    tpstart "Set to monitor mode, then unload driver"
    iwl_load_module
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    ifconfig wlan0 up
    sleep 3
    modprobe iwlagn -r || { iwl_fail; break; }
    modprobe iwl3945 -r || { iwl_fail; break; }
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
