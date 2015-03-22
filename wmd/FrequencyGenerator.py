#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  wmd_launcher.py
#
#  Copyright 2013 Brandon Knight <kaospunk@gmail.com>
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

import alsaaudio
import sys
import time
from math import pi, sin
from numpy import arange        # like range, but supports floating point

A = 440
D = 293.66
F = 349.23
C = 523.25
C4 = 261.63
C3 = 130.81
B = 493.88
D5= 587.33
G = 392.00
C4 = 261.63
D4 = 293.66
E4 = 329.63
Gab4 = 415.30
G3 = 196.0
B2 = 123.47
B3_flat = 233.08
A3 = 220.00
D4l = 311.13
song_of_time_notes = [A, A, D, D, D, D, F, F, A, A, D, D, D, D, F, F, A, C, B, B, G, G, F, G, A, A, D, D, C4, E4, D, D, D, D]

class FrequencyGenerator:
	def __init__(self, channels = 2, sample_size = 1, frame_rate = 44100, period_size = 11025):
		self.channels = channels
		self.sample_size = sample_size
		self.frame_size = self.channels * self.sample_size
		self.frame_rate = frame_rate
		self.byte_rate = self.frame_rate * self.frame_size # bytes per second
		self.period_size = period_size

		self.pcm = alsaaudio.PCM(alsaaudio.PCM_PLAYBACK)
		self.pcm.setchannels(self.channels)
		self.pcm.setformat(alsaaudio.PCM_FORMAT_U8)
		self.pcm.setrate(self.frame_rate)
		self.pcm.setperiodsize(self.period_size)

	def quantize(self, f):           # map (-1..1) -> [0..256)
		return int((f+1)*127)       # depends on PCM format

	def sine_wave(self, freq):
		wave = [chr(self.quantize(sin(x))) * self.channels for x in arange(0, 2*pi, 2*pi / (self.frame_rate/freq))]
		wave_data = "".join(wave) + "".join(wave)
		(nwaves, extra_bytes) = divmod(self.period_size * self.frame_size, len(wave_data))
		self.pcm.write((wave_data * nwaves) + wave_data[:extra_bytes])

	def play_zelda(self):
		zelda = [C4, C4, G3, G3, G3, G3, C4, C4, D4, D4l, F, G]
		for note in zelda:
			self.sine_wave(note)

	def zelda_secret(self):
		G = 783.99
		Fs = 739.99
		Ds = 622.25
		Gs = 415.30
		E = 659.26
		HGs = 830.61
		HC = 1046.50
		secret = [G, Fs, Ds, A, Gs, E, HGs, HC]
		for note in secret:
			self.sine_wave(note)

def main():
	t = FrequencyGenerator()
	t.zelda_secret()

if __name__ == "__main__":
	main()
