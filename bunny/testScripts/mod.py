#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    bunny.py
#
#    Copyright 2013 W. Parker Thompson <w.parker.thompson@gmail.com>
#		
#    This file is part of Bunny.
#
#    Bunny is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Bunny is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Bunny.  If not, see <http://www.gnu.org/licenses/>.

import sys
mod = 1.23
remain = 0.82

if len(sys.argv) > 2:
	mod = float(sys.argv[1])
	remain = float(sys.argv[2])

print ("Mod:\t%f" % mod)
print ("Remain:\t%f" % remain)

for i in range(1, 400):
	if round( i % mod, 2) == remain:
		print i
