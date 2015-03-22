#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
#    Copyright 2008-2011 Lukas Lueg, lukas.lueg@gmail.com
#
#    This file is part of Pyrit.
#
#    Pyrit is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Pyrit is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Pyrit.  If not, see <http://www.gnu.org/licenses/>.


from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
from distutils.command.clean import clean
import os
import re
import subprocess
import sys

VERSION = '0.4.1-dev' 

try:
    svn_info = subprocess.Popen(('svn', 'info'), \
                                stdout=subprocess.PIPE).stdout.read()
    VERSION += ' (svn r%i)' % \
                int(re.compile('Revision: ([0-9]*)').findall(svn_info)[0])
except:
    pass
EXTRA_COMPILE_ARGS = ['-DVERSION="%s"' % (VERSION,)]

null_extension = Extension('cpyrit._cpyrit_null',
                    sources = ['_cpyrit_null.c'],
                    extra_compile_args=EXTRA_COMPILE_ARGS)

setup_args = dict(
        name = 'cpyrit-null',
        version = VERSION,
        description = 'GPU-accelerated attack against WPA-PSK authentication',
        license = 'GNU General Public License v3',
        author = 'Lukas Lueg',
        author_email = 'lukas.lueg@gmail.com',
        url = 'http://pyrit.googlecode.com',
        ext_modules = [null_extension],
        options = {'install': {'optimize':1}, \
                   'bdist_rpm': {'requires': 'pyrit = 0.4.0-1'}})

if __name__ == "__main__":
    setup(**setup_args)
