#!/bin/bash
#
#Copyright (c) 2006 - 2009, Intel Corporation
#Author: ximin.luo@intel.com
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
cd /usr/tet/TVS/Reports/latest

if [ -f FullReport.txt ]; then
	head -n 3 FullReport.txt> Function.txt
	head -n 3 FullReport.txt> Performance.txt
	grep "^perf" FullReport.txt >> Performance.txt
	grep -v "^perf" FullReport.txt |grep -v "Test Report" |grep -v "^tpname" |grep -v "============" >> Function.txt
	sed s/'Test Report of Last Session'/'Detail Test Report'/g Function.txt > tmp.txt
	mv tmp.txt Function.txt
	sed s/'Test Report of Last Session'/'Performance Test Report'/g Performance.txt >tmp1.txt
	mv tmp1.txt Performance.txt
else
	echo "No FullReport.txt"
fi

#3945 card
lspci -n | grep 8086:4222 && card=3945
lspci -n | grep 8086:4227 && card=3945
#4965 card
lspci -n | grep 8086:4229 && card=4965
lspci -n | grep 8086:4230 && card=4965
#5100 card
lspci -n | grep 8086:4232 && card=5100
lspci -n | grep 8086:4237 && card=5100
#5300 card
lspci -n | grep 8086:4235 && card=5300
lspci -n | grep 8086:4236 && card=5300

os=`uname -a | awk '{print tolower($12)}'`
case $os in
    x86_64)
        osMode=64bit
        ;;
    i686)
        osMode=32bit
        ;;
    *)
        ;;
esac

echo "card= $card" >> Performance.txt
echo "osMode= $osMode">> Performance.txt
