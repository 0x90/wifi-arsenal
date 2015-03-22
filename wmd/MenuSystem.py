#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  MenuSystem.py
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

import subprocess
from LCD import *
from time import sleep
from Aircrack import *
from FrequencyGenerator import FrequencyGenerator

class MenuSystem:
	iwconfig_bin = "/sbin/iwconfig"

	def __init__(self):
		self.lcd = LCD()
		self.rogue_aps = []

	def wlan_menu(self):
		wireless_cards = []
		current_pointer = 0
		wlan = subprocess.Popen([self.iwconfig_bin], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		while True:
			line = wlan.stdout.readline()
			if not line:
				break
			elif "wlan" in line:
				wireless_cards.append(line.split(" ")[0])

		if wireless_cards > 0:
			self.lcd.display("Select wlan:\n{0}".format(wireless_cards[current_pointer]))
			while True:
				result = self.lcd.get_button_press()
				if result == "Up":
					current_pointer -= 1
					if abs(current_pointer) == len(wireless_cards):
							current_pointer = 0
					self.lcd.display("Select wlan:\n{0}".format(wireless_cards[current_pointer]))
				elif result == "Down":
					current_pointer += 1
					if abs(current_pointer) == len(wireless_cards):
							current_pointer = 0
					self.lcd.display("Select wlan:\n{0}".format(wireless_cards[current_pointer]))
				elif result == "Select":
					self.lcd.display("Starting\nDetection")
					self.airmon = Airmon(wireless_cards[current_pointer])
					self.airmon.start()
					self.airodump_main = Airodump(self.lcd)
					self.airodump_main.start()
					break

	def main_menu(self):
		list = ['View Rogues','Update Whitelist','Backup Files','Clear Rogues','Restart Monitoring']
		current_pointer = 0
		secret_counter = 0
		tone = FrequencyGenerator()
		while True:
			self.lcd.display("Main Menu:\n{0}".format(list[current_pointer]))
			result = self.lcd.get_button_press()
			if result == "Up":
				current_pointer -= 1
				if abs(current_pointer) == len(list):
					current_pointer = 0
			elif result == "Down":
				current_pointer += 1
				if abs(current_pointer) == len(list):
					current_pointer = 0
			elif result == "Left":
				secret_counter += 1
				if secret_counter == 3:
					self.lcd.set_color("green")
					tone.zelda_secret()
					secret_counter = 0
			elif result == "Select":
				if list[current_pointer] == 'Update Whitelist':
					result = self.airodump_main.update_whitelist()
					self.lcd.display(result, 2)
				elif list[current_pointer] == 'Backup Files':
					result = self.airodump_main.backup_files()
					self.lcd.display(result, 2)
				elif list[current_pointer] == 'View Rogues':
					self.networks_menu()
				elif list[current_pointer] == 'Clear Rogues':
					self.airodump_main.clear_rogues()
					self.lcd.display("Rogues cleared", 2)
				elif list[current_pointer] == 'Restart Monitoring':
					self.lcd.display("Restarting")
					self.airmon.restart()
					self.airodump_main.restart()
					self.lcd.display("Restarted", 2)

	def networks_menu(self):
		rogue_aps = self.airodump_main.rogue_aps
		if len(rogue_aps) < 1:
			self.lcd.display("No Rogue APs", 2)
			return
		current_pointer = 0
		self.lcd.display("Potential Target\n{0}".format(rogue_aps[current_pointer][0]))
		while True:
			rogue_aps = self.airodump_main.rogue_aps
			result = self.lcd.get_button_press()
			if result == "Up":
				current_pointer -= 1
				if abs(current_pointer) == len(rogue_aps):
					current_pointer = 0
				self.lcd.display("Potential Target\n{0}".format(rogue_aps[current_pointer][0]))
			elif result == "Down":
				current_pointer += 1
				if abs(current_pointer) == len(rogue_aps):
					current_pointer = 0
				self.lcd.display("Potential Target\n{0}".format(rogue_aps[current_pointer][0]))
			elif result == "Left":
				break
			elif result == "Select":
				self.airodump_main.stop()
				target_airodump = Airodump(self.lcd, rogue_aps[current_pointer][0], rogue_aps[current_pointer][1], rogue_aps[current_pointer][2])
				target_airodump.locate()
				self.lcd.display("Potential Target\n{0}".format(rogue_aps[current_pointer][0]))
				self.airodump_main.start()

def main():
	menu = MenuSystem()
	menu.wlan_menu()
	menu.main_menu()

if __name__ == "__main__":
	main()
