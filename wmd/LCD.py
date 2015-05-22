#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  LCD.py
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

from Adafruit_CharLCDPlate import *
from time import sleep

class LCD:
	def __init__(self):
		self.lcd = Adafruit_CharLCDPlate()
		self.lcd.begin(16, 2)
		sleep(0.5)
		self.colors =   (('red', self.lcd.RED),  ('yellow', self.lcd.YELLOW), ('green',  self.lcd.GREEN),
						('teal', self.lcd.TEAL), ('blue',  self.lcd.BLUE),    ('violet', self.lcd.VIOLET),
						('off',  self.lcd.OFF),  ('on',    self.lcd.ON))
		self.buttons =  ((self.lcd.SELECT, 'Select'),
						(self.lcd.LEFT,    'Left'),
						(self.lcd.UP,      'Up'),
						(self.lcd.DOWN,    'Down'),
						(self.lcd.RIGHT,   'Right'))
		self.lcd.backlight(self.lcd.BLUE)
		self.color = self.lcd.BLUE
		self.lcd.clear()

	def get_color(self, color):
		for color_main in self.colors:
			if color == color_main[0]:
				return color_main[1]

	def set_color(self, color):
		self.lcd.backlight(self.get_color(color.lower()))

	def display(self, message, duration = 0, color = None):
		if color is not None and color != self.color:
			self.lcd.backlight(self.get_color(color))
		self.lcd.clear()
		self.lcd.message(message)
		if duration != 0:
			sleep(duration)
			self.lcd.clear()

	def wipe(self):
		self.lcd.backlight(self.color)
		self.lcd.clear()

	def color_cycle(self):
		for color in self.colors:
			self.lcd.backlight(color[1])
			sleep(0.1)

	def get_button_press(self, block = True):
		sleep(0.5)
		while True:
			for button in self.buttons:
				if self.lcd.buttonPressed(button[0]):
					return button[1]
			if not block:
				break

def main():
	l = LCD()
	l.color_cycle()
	l.display("This is some text",3)
	l.set_color("Green")

if __name__ == "__main__":
	main()
