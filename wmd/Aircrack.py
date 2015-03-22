#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Aircrack.py
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

import calendar
import datetime
import glob
import os
import shutil
import subprocess
import time
from Adafruit_CharLCDPlate import *
from EspeakDriver import EspeakDriver
from FrequencyGenerator import FrequencyGenerator
from LCD import *
from threading import Thread, Event
from xml.etree import ElementTree

class Airmon:
	airmon_bin = "/usr/sbin/airmon-ng"
	iwconfig_bin = "/sbin/iwconfig"

	def __init__(self, interface):
		self.interface = interface

	def stop(self):
		subprocess.Popen([self.airmon_bin, "stop", "mon0"], bufsize=0, stdout=open(os.devnull, "w"), stderr=open(os.devnull, "w"))
		time.sleep(5)

	def start(self):
		airmon = subprocess.Popen([self.airmon_bin, "start", self.interface], bufsize=0, stdout=open(os.devnull, "w"), stderr=open(os.devnull, "w"))
		time.sleep(5)

	def restart(self):
		self.stop()
		self.start()

class Airodump:
	base_dir = '/home/securestate/'
	airodump_bin = '/usr/sbin/airodump-ng'
	whitelist_file = 'apwhitelist.txt'
	usb_dir = '/media/usbdevice/'
	MINIMUM_SIGNAL = -110

	def __init__(self, lcd, essid = None, bssid = None, channel = None):
		self.bssid = bssid
		self.channel = channel
		self.essid = essid
		if essid == None:
			self.capture_file = "main"
		else:
			self.capture_file = bssid.replace(":", "_") + essid
		self.lcd = lcd
		self.tone = FrequencyGenerator()
		self.rssi_event = Event()
		self.parse_event = Event()
		self.espeak_drv = EspeakDriver()
		self.rogue_aps = []
		self.good_aps = []
		self.get_whitelist()

	def stop(self):
		self.proc_handle.terminate()
		time.sleep(5)
		self.parse_event.clear()

	def start(self):
		if self.capture_file == "main":
			self.proc_handle = subprocess.Popen([self.airodump_bin, "-w", "main", "mon0"], bufsize=0, stdout=open(os.devnull, "w"), stderr=open(os.devnull, "w"))
			self.parse_event.set()
			self.parse_thread = Thread(target=self.parser)
			self.parse_thread.daemon = True
			self.parse_thread.start()
		else:
			self.proc_handle = subprocess.Popen([self.airodump_bin, "--bssid", self.bssid, "--channel", self.channel, "-w", self.capture_file, "mon0"], bufsize=0, stdout=open(os.devnull, "w"), stderr=open(os.devnull, "w"))

	def restart(self):
		self.stop()
		self.start()

	def locate(self):
		self.lcd.set_color("red")
		self.lcd.display("Locking on")
		self.start()
		self.rssi_event.set()
		self.rssi = Thread(target=self.rssi_tone)
		self.rssi.start()

		while self.rssi.is_alive() and self.lcd.get_button_press(False) != "Select":
			pass
		self.rssi_event.clear()
		break

		self.stop()
		self.lcd.wipe()
		return

	def rssi_tone(self):
		if self.capture_file == "main":
			return
		signal = True
		time.sleep(5)
		latest_file = self.get_latest_file()
		print "Using " + latest_file
		while True and signal:
			if not self.rssi_event.is_set():
				break
			try:
				tree = ElementTree.parse(latest_file)
			except:
				continue
			root = tree.getroot()
			for network in root.findall("wireless-network"):
				rssi = network.find("snr-info/last_signal_rssi").text
				print rssi
				essid = network.find("SSID/essid").text
				last_seen = network.get("last-time")
				print last_seen
				(dow, month, day, ltime, year) = last_seen.split()
				for mon in xrange(1, 13):
					if calendar.month_abbr[mon] == month:
						break
				(hour, minute, second) = ltime.split(":")
				lastseen = datetime.datetime(int(year), mon, int(day), int(hour), int(minute), int(second))
				delta = datetime.datetime.now() - lastseen
				print "Delta " + str(delta)
				if delta.total_seconds() > 60:
					self.lcd.display("Signal Lost", 2)
					signal = False
					self.rssi_event.clear()
					break
				abs_value = abs(int(rssi))
				freq = float(2.5/abs_value) * 10000
				self.lcd.display("Target: {0}dbm\n{1}".format(rssi, essid))
				self.tone.sine_wave(freq)

	def get_signal_strength(self, bssid):
		if self.capture_file == "main":
			return
		file = self.get_latest_file()
		tree = ElementTree.parse(file)
		root = tree.getroot()
		for network in root.findall("wireless-network"):
			if network.find("BSSID").text == bssid:
				return network.find("snr-info/last_signal_rssi")

	def get_latest_file(self):
		latest_track = 0
		latest_file = ''
		for file in glob.glob(self.base_dir + self.capture_file + "*.kismet.netxml"):
			pieces = file.split("-")
			number = pieces[-1].split(".")[0]
			if number > latest_track:
				latest_track = number
				latest_file = file
		return latest_file

	def get_whitelist(self):
		ap_file = open(self.base_dir + self.whitelist_file, 'r')
		for ap in ap_file:
			self.good_aps.append(ap.rstrip())

	def clear_rogues(self):
		del self.rogue_aps[:]

	def parser(self):
		latest_file = self.get_latest_file()
		time.sleep(5)
		while self.parse_event.is_set():
			try:
				tree = ElementTree.parse(latest_file)
			except:
				continue
			root = tree.getroot()
			for network in root.findall("wireless-network"):
				rssi = int(network.find("snr-info/last_signal_rssi").text)
				essid = network.find("SSID/essid").text
				bssid = network.find("BSSID").text
				channel = network.find("channel").text
				found = False
				for rogue in self.rogue_aps:
					if rogue[1] == bssid:
						found = True
				if not found and bssid not in self.good_aps and rssi > self.MINIMUM_SIGNAL:
					self.rogue_aps.append((essid, bssid, channel))
					print("New rogue AP found with name: {0}").format(essid)
					self.espeak_drv.speak('New Rogue AP found with name {0}'.format(essid))

	def update_whitelist(self):
		del self.good_aps[:]
		try:
			source_file = open(self.usb_dir + self.whitelist_file, 'r')
			output_string = ''
			for ap in source_file:
				self.good_aps.append(ap.rstrip())
				output_string += ap
				for rogue in self.rogue_aps:
					if rogue[1] == ap.rstrip():
						self.rogue_aps.remove(rogue)
			dest_file = open(self.base_dir + self.whitelist_file, 'w')
			dest_file.write(output_string)
			return "Success"
		except Exception as e:
			return "Error occurred"

	def backup_files(self):
		try:
			for file in glob.glob(self.base_dir + "*.csv"):
				shutil.copy(file, self.usb_dir + file.split("/")[-1])
			for file in glob.glob(self.base_dir + "*.cap"):
				shutil.copy(file, self.usb_dir + file.split("/")[-1])
			for file in glob.glob(self.base_dir + "*.netxml"):
				shutil.copy(file, self.usb_dir + file.split("/")[-1])
			return "Success"
		except Exception:
			return "Error occurred"

def main():
	lcd = LCD()
	airmon = Airmon("wlan0")
	airmon.start()
	main_airdump = Airodump(lcd)
	main_airdump.start()
	for x in xrange(100):
		print str(x)
		time.sleep(1)
	main_airdump.stop()
	print "done"

if __name__ == "__main__":
	main()
