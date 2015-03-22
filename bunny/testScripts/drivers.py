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

import pylorcon

cards = pylorcon.getcardlist()

# ebay search string:
#	Without Alpha:
# 	("AWLL3026", "NT-WGHU", "WUSB54GC", Netgear WG111, "Asus WL-167g v2", "Digitus DN-7003GS", "D-Link DWL-G122", "D-Link WUA-1340", "Hawking HWUG1", "Linksys WUSB54G v4")
#
#	With Alpha:
#	("Alfa AWUS036E", "Alfa AWUS036H", "Alfa AWUS036S", "Alfa AWUS050NH", "Asus WL-167g v2", "Digitus DN-7003GS", "D-Link DWL-G122", "D-Link WUA-1340", "Hawking HWUG1", "Linksys WUSB54G v4")
#
# always cross ref with: http://www.aircrack-ng.org/doku.php?id=compatibility_drivers

for card in cards:
	print card['name']

