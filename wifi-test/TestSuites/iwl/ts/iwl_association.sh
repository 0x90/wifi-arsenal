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

dir=`dirname $0`
. $dir/tvs_env
. $dir/iwl_env.sh
. $dir/iwl_common.sh
#. ../tvs_env
#. ./iwl_common.sh
tet_infoline()
{
echo $@
}

iwl_load_module
iwl_connect $@
i=1
while [ $i -lt 30 ]; do
iwconfig wlan0 |grep Not-Associated || break
sleep 2
i=$((i+1))
echo $i
done

[ $i -lt 30 ] || exit 1

