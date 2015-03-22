#! /usr/bin/python

"""
	-*- coding: utf-8 -*-
	setup.py
	
	Author: Spencer McIntyre <smcintyre [at] securestate [dot] com>
	
	Copyright 2011 SecureState
	
	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
	MA 02110-1301, USA.

"""

from distutils.core import setup
from os import listdir
from sys import version_info as version

py_modules = [ 'ipfunc' ]
if version[0] == 2 and version[1] < 7:
	py_modules.append('argparse')

setup(
	name = 'EAPeak',
	version = '0.1.4',
	description = 'EAPeak Wireless Analysis Suite',
	
	# Author
	author = 'Spencer McIntyre',
	author_email = 'SMcIntyre [at] SecureState [dot] com',
	
	# Maintainer
	maintainer = 'Spencer McIntyre',
	maintainer_email = 'SMcIntyre [at] SecureState [dot] com',
	
	url = 'http://www.securestate.com/',
	download_url = 'http://www.securestate.com/',
	
	# EAPeak's required packages
	requires = [ 'scapy', 'M2Crypto' ],
	
	# EAPeak's package data
	provides = [ 'eapeak' ],
	packages = [ 'eapeak' ],
	package_dir = { '': 'lib' },
	py_modules = py_modules,
	
	scripts = [ 'eapeak', 'eapscan', 'eapwn' ],
	data_files = [	
					('/usr/share/man/man1', ['data/man/eapeak.1.gz', 'data/man/eapscan.1.gz', 'data/man/eapwn.1.gz'])
					]
	)
