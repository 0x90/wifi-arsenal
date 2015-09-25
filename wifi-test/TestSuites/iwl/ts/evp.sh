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

tet_startup="startup"    		# startup function
tet_cleanup="cleanup"    		# cleanup function

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7"
ic1="Build_iwm"
ic2="Build_top"

Build_iwm()
{
    iwl_tpstart "Build iwm"
    repo_dir=$TVS_ROOT/tsets/iwl/
    rm -rf $repo_dir/iwm
    cd $repo_dir
    git clone git://viggo.jf.intel.com/~wifi/iwm.git
    cd iwm
    make || iwl_fail "Make failed"
    make modules_install || iwl_fail "Module install failed"
    tpresult
}

Build_top()
{
    iwl_tpstart "Build top"
    repo_dir=$TVS_ROOT/tsets/iwl/
    rm -rf $repo_dir/iwmc3200top
    cd $repo_dir
    git clone git://cook.jer.intel.com/iwmc3200top.git
    cd iwmc3200top
    make || iwl_fail "Make failed"
    make modules_install || iwl_fail "Module install failed"
    tpresult
}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

set -x
# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh
