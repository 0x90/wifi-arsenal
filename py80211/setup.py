#!/usr/bin/env python
# This file is copyright Ben Smith AKA Textile, licensed under the GPL3 License.

from distutils.core import setup

setup(name='py80211',
    version='1.0',
    description='Lib suite for reading/writing 80211 packets',
    author='Textile & Crypt0s',
    license='GPL2',
    classifiers=[ 'Development Status :: 4 - Beta'],
    py_modules = ['Parse80211', 'Tool80211', 'Gen80211', 'liboui2',  'wifiobjects'],
    )
