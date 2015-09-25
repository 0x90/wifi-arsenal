# Copyright (c) <2002>, Intel Corporation
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the following 
# conditions are met:
# 
# Redistributions of source code must retain the above copyright 
# notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright 
# notice, this list of conditions and the following disclaimer in
# the documentation and/or other materials provided with the distribution.
# 
# Neither the name of Intel Corporation, nor the names 
# of its contributors may be used to endorse or promote products 
# derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
# OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

###############################################################################
## Makefile (TVS)
##
## Rusty Lynch <rusty.lynch@intel.com>
## Xiaofeng Ling <xiaofeng.ling@intel.com>
#Author: Jeff Zheng <jeff.zheng@intel.com>
#Contact: WiFi Test Development <wifi-test-devel@lists.sourceforge.net>
###############################################################################
##   Copyright (c) OSDL 2002
##
###############################################################################

######################################################################
# This makefile works on the assumption that the below named RPM spec
# file exist in the same directory, and that the correct project name,
# version, and release are all contained in the spec file.
# 
# These are the only variables that should ever need adjustment
RPM_ROOT   := $(shell grep '%_topdir' /usr/lib/rpm/macros | cut -d'/' -f2)

ifeq ($(RPM_ROOT),)
	RPM_ROOT := /usr/src/packages	# Redundant Check
else
	RPM_ROOT := /usr/src/$(RPM_ROOT)
endif

SPECFILE=tvs.spec
SPEC_NAME=tvs.spec
SUBDIRS=
RPM_BUILD_DEPS=tet_testsuite_dependency
#
######################################################################

NAME         = `awk '/Name:/{print $$2}' $(SPEC_NAME)`
VERSION      = `awk '/Version:/{print $$2}' $(SPEC_NAME)`
RELEASE      = `awk '/Release:/{print $$2}' $(SPEC_NAME)`
ARCHIVE_NAME = $(NAME)-$(VERSION).$(RELEASE).tgz
LINK_NAME    = $(NAME)-$(VERSION)

all: 
	make -C src all
build:
	make -C src build

install: build
	make -C src install

rpm: rpm_build_deps build_link
	echo "Building RPM"
	tar cvhfz $(ARCHIVE_NAME) $(LINK_NAME)
	cp $(NAME)-$(VERSION).$(RELEASE).tgz $(RPM_ROOT)/SOURCES/
	cp $(SPECFILE) $(RPM_ROOT)/SPECS/
	rpmbuild --define="_topdir $(RPM_ROOT)" -ba $(RPM_ROOT)/SPECS/$(SPECFILE)

rpm_build_deps:
	/bin/bash ./installRequiredRPMs.sh ${RPM_BUILD_DEPS}

build_link: cleanup_build_link
	ln -s src $(LINK_NAME)

clean_rpm:
	rm -fr $(RPM_ROOT)/BUILD/$(NAME)-$(VERSION)
	rm -f  $(RPM_ROOT)/SOURCES/$(ARCHIVE_NAME)
	rm -f  $(RPM_ROOT)/SPECS/$(SPEC_NAME)

cleanup_build_link:
	rm -rf $(LINK_NAME)

clean: cleanup_build_link clean_rpm
	make -C src clean
	rm -f core *.tgz *~

about:
	echo "Name   : $(NAME)"
	echo "Version: $(VERSION)"
	echo "Release: $(RELEASE)"
	echo "Spec   : $(SPEC_NAME)"

.SILENT:



