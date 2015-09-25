#!/bin/bash

# Copyright © 2002 OSDL.
# Initial Authors:  julie.n.fleischer@intel.com, rusty.lynch@intel.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# Neither the name of the OSDL nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


if [ -z $RPM_ROOT ]; then
  echo "Using default RPM_ROOT!"
  RPM_ROOT=/usr/src/packages
fi

# All of the RPM install stuff can 
# be turned off by setting 
if [ -z $BYPASS_RPM_INSTALL ]; then
  echo "Installing required RPMs: To disable the automatic install of "
  echo "                          build time dependencies, export"
  echo "                          BYPASS_RPM_INSTALL to any value."
  for target in $*
  do
    #only install RPM if not already installed
    rpm -qa | grep $target
    if [ $? -eq 1 ]; then
        echo "installing $target..."
        rpm -ivh $RPM_ROOT/RPMS/$HOSTTYPE/$target-*rpm
    fi
  done
fi


