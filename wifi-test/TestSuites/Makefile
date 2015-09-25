# Copyright (C)  <2006>, Intel Corporation
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
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
# 
# VARIABLES WHICH CAN BE MODIFIED
TESTSUITES = `ls */Makefile | sed "s/Makefile//g"`

all: 
	@set -e; for i in $(TESTSUITES); do make -C $$i ; done

install:
	@set -e; for i in $(TESTSUITES); do make -C $$i install; done

clean:
	@set -e; for i in $(TESTSUITES); do make -C $$i clean; done

