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

tet_startup="startup"               # startup function
tet_cleanup="cleanup"               # cleanup function
iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7"
ic1="NT1"
ic2="NT2"
ic3="NT3"
ic4="NT6"
ic5="NT7_1"
ic6="NT7_2"
ic7="NT10"



NT1()
{
    tpstart "BSS invalid essid"
    iwl_load_module
    iwl_apset && iwl_connect -s "${iwl_essid}b" && iwl_check  ${iwl_srv[1]}
    [ $? -ne 0 ] || iwl_fail # Should not be able to connect
    tpresult
}

NT2()
{
    tpstart "BSS change essid"
    iwl_load_module
    iwl_test || iwl_fail
    iwl_connect -s "${iwl_essid}b" && iwl_check  ${iwl_srv[1]}
    [ $? -ne 0 ] || iwl_fail # Should not be able to connect
    tpresult
}

NT3()
{
    tpstart "BSS invalid MAC"
    iwl_load_module
    iwl_apset && iwl_connect -A "00:11:22:33:44:55" && iwl_check  ${iwl_srv[1]}
    [ $? -ne 0 ] || iwl_fail # Should not be able to connect
    tpresult
}

NT6()
{
    tpstart "BSS ssid any"
    iwl_load_module
    iwl_apset -b disable 
    iwl_connect -s any && iwl_check  ${iwl_srv[1]}
    [ $? -ne 0 ] || { iwl_fail; break; }
    tpresult
}

NT7_1()
{
    tpstart "IBSS 2 DUTs on different channel"
    iwl_load_module
    iwl_test_ibss -c ${iwl_chans[0]} || iwl_fail
    essid=${iwl_host[0]}-ibss # Refer to iwl_test_ibss
    iwl_connect -s $essid $@ -i -c ${iwl_chans[1]} && iwl_check ${iwl_peer[1]}
    [ $? -ne 0 ] || iwl_fail # should not connect
    tpresult
}
 
NT7_2()
{
    tpstart "IBSS 2 DUTs with different essid"
    iwl_load_module
    iwl_test_ibss -c ${iwl_chans[0]} || iwl_fail
    essid=${iwl_host[0]}-wrong # Refer to iwl_test_ibss
    iwl_connect -s $essid $@ -i -c ${iwl_chans[0]} && iwl_check ${iwl_peer[1]}
    [ $? -ne 0 ] || iwl_fail # should not connect
    tpresult
}

NT10()
{
    tpstart "Associate NOWEP AP with key"
    iwl_load_module
    iwl_apset 
    iwl_connect -k 1 && iwl_check  ${iwl_srv[1]}
    [ $? -ne 0 ] || { iwl_fail; break; }
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh

