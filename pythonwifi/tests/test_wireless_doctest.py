#!/usr/bin/env python
# Copyright 2004-2008 Roman Joost <roman@bromeco.de> - Rotterdam, Netherlands
# this file is part of the python-wifi package - a python wifi library
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
import doctest
import iwlibs
import pyiwconfig

def _test_pyiwconfig():
    return doctest.testmod(pyiwconfig)

def _test_iwlibs():
    return doctest.testmod(iwlibs)

if __name__ == "__main__":
    _test_iwlibs()
    _test_pyiwconfig()
