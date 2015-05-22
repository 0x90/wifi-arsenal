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

import os, sys, struct

from keyczar.errors import InvalidSignatureError
from keyczar.keys import AesKey

from config import *

class AEScrypt:
	"""
	
	Class for encrypting and decrypting AES256 data.
	
	"""
	
	def __init__(self):
		# check if the key.kz file exists
		try:
			with open("keys.kz", "r") as fd:
				data = fd.read()
		except IOError:
			print "ERROR: no key file found, generating the file"
			self.key = AesKey.Generate()
			with open("keys.kz", "w+") as fd:
				fd.write(str(self.key))
		else:
			self.key = AesKey.Read(data)
			if DEBUG:
				print self.key.key_string
				print self.key.hmac_key
		
		# If keyczar changes their header format this would need to change:
		#  5 bytes for the header and 16 for the IV
		self.header_len = 5 + 16
		self.block_len = self.key.block_size
		self.hmac_len = self.key.hmac_key.size/8
		self.overhead = self.header_len + self.hmac_len
		
	def encrypt(self, data):
		
		# returns a block of string of cipher text.
		output = self.key.Encrypt(data)		
		return output
		
	def decrypt(self, data):
		
		try:
			output = self.key.Decrypt(data)
		except InvalidSignatureError:
			if DEBUG:
				print "ERROR: Invalid Signature, either there was a corruption or there was an attempted attack"
			return False
		except:
			# TODO: what exception is causing this?
			print "ERROR: Failed to decrypt the packet"
			if DEBUG:
				print "Exception: \n" + str(sys.exc_info()[0])
			return False
		
		return output
		
