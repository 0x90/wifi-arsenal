# Copyright (c) 2006 - 2009, Intel Corporation
#Author: Jeff Zheng <jeff.zheng@intel.com>
#Contact: WiFi Test Development <wifi-test-devel@lists.sourceforge.net>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

DEPTH = ../../tvs/src

all install:
	mkdir -p  ${DEPTH}/tsets/iwl
	cp README tet_scen tvs_env ${DEPTH}/tsets/iwl
	rm -rf ${DEPTH}/tsets/iwl/ts
	cp -rf ts ${DEPTH}/tsets/iwl

clean:
	rm -rf ${DEPTH}/tsets/iwl/*

