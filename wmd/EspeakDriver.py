#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  espeak.py
#
#  Copyright 2013 Spencer McIntyre <zeroSteiner@gmail.com>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import subprocess

class EspeakDriver(object):
	def __init__(self, bin_path = '/usr/bin/espeak', volume = 100, speed = 175):
		self.bin_path = bin_path
		self.volume = volume
		self.speed = speed

	def speak(self, text, volume = None, speed = None):
		volume = (volume or self.volume)
		speed = (speed or self.speed)
		espeak_proc = subprocess.Popen([self.bin_path, '-v', 'en+f3', '-a', str(volume), '-s', str(speed), text, "--stdout"], stdout = subprocess.PIPE, stderr = open("/dev/null", "w"))
		aplay = subprocess.Popen(["/usr/bin/aplay"], stdin = espeak_proc.stdout, stdout = open("/dev/null", "w"), stderr = open("/dev/null", "w"))
		aplay.wait()

	def say(self, text):
		self.speak(text)

	def warn(self, text):
		self.yell('Warning ' + text)

	def whisper(self, text):
		self.speak(text, volume = 50)

	def yell(self, text):
		self.speak(text, volume = 200)

def main():
	espeak_drv = EspeakDriver()
	espeak_drv.speak('Hello World!')
	return 0

if __name__ == '__main__':
	main()
