#!/usr/bin/python
# taken from: https://code.google.com/p/pyrocket/
# where it is licensed under the GNU GPLv3 (c)

import usb

class RocketManager:
	vendor_product_ids = [(0x1941, 0x8021), (0x0a81, 0x0701), (0x0a81, 0xff01), (0x1130, 0x0202), (0x2123,0x1010)]
	launcher_types = ["Original", "Webcam", "Wireless", "Striker II", "OIC Webcam"]
	housing_colors = ["green", "blue", "silver", "black", "gray"]

	def __init__(self):
		self.launchers = []

	# -----------------------------

	def acquire_devices(self):

		device_found = False



		for bus in usb.busses():
			for dev in bus.devices:
				for i, (cheeky_vendor_id, cheeky_product_id) in enumerate(self.vendor_product_ids):
					if dev.idVendor == cheeky_vendor_id and dev.idProduct == cheeky_product_id:

						#print "Located", self.housing_colors[i], "Rocket Launcher device."

						launcher = None
						if i == 0:
							launcher = OriginalRocketLauncher()
						elif i == 1:
							launcher = BlueRocketLauncher()
						elif i == 2:
#							launcher = BlueRocketLauncher()	# EXPERIMENTAL
							return '''The '''+self.launcher_types[i]+''' ('''+self.housing_colors[i]+''') Rocket Launcher is not yet supported.  Try the '''+self.launcher_types[0]+''' or '''+self.launcher_types[1]+''' one.'''
						elif i == 3:
							launcher = BlackRocketLauncher()
						elif i == 4:
							launcher = GrayRocketLauncher()

						return_code = launcher.acquire( dev )
						if not return_code:
							self.launchers.append( launcher )
							device_found = True

						elif return_code == 2:
							string = '''You don't have permission to operate the USB device.  To give
yourself permission by default (in Ubuntu), create the file
/etc/udev/rules.d/40-missilelauncher.rules with the following line:
SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ACTION=="add", SYSFS{idVendor}=="%04x", SYSFS{idProduct}=="%04x", GROUP="plugdev", MODE="0660"
The .deb installer should have done this for you.  If you just installed
the .deb, you need to unplug and replug the USB device now.  This will apply
the new permissions from the .rules file.''' % (cheeky_vendor_id, cheeky_product_id)
							print string

							return '''You don't have permission to operate the USB device.
If you just installed the .deb, you need to plug cycle the USB device now.  This will apply
the new permissions from the .rules file.'''



		if not device_found:
			return 'No USB Rocket Launcher appears\nto be connected.'


# ============================================
# ============================================

class OriginalRocketLauncher:

	color_green = True
	has_laser = False

	green_directions = [1, 0, 2, 3, 4]

	def __init__(self):

		self.usb_debug = True

		self.previous_fire_state = False
		self.previous_limit_switch_states = [False]*4	# Down, Up, Left, Right

	# ------------------------------------------------------
	def acquire(self, dev):

		self.handle = dev.open()

		try:
			self.handle.reset()

		except usb.USBError, e:
			if e.message.find("not permitted") >= 0:
				return 2
			else:
				raise e


#		self.handle.setConfiguration(dev.configurations[0])

		try:
			self.handle.claimInterface( 0 )
		except usb.USBError, e:
			if e.message.find("could not claim interface") >= 0:
				self.handle.detachKernelDriver( 0 )
				self.handle.claimInterface( 0 )

		self.handle.setAltInterface(0)

		return 0

	# -----------------------------
	def issue_command(self, command_index):

		signal = 0
		if command_index >= 0:
			signal = 1 << command_index

		try:
			self.handle.controlMsg(0x21, 0x09, [signal], 0x0200)

		except usb.USBError:
			pass

	# -----------------------------
	def start_movement(self, command_index):
		self.issue_command( self.green_directions[command_index] )

	# -----------------------------
	def stop_movement(self):
		self.issue_command( -1 )

	# -----------------------------
	def check_limits(self):
		'''For the "green" rocket launcher, the MSB of byte 2 comes on when a rocket is ready to fire,
		and is cleared again shortly after the rocket fires and cylinder is charged further.'''

		bytes = self.handle.bulkRead(1, 8)


		if self.usb_debug:
			print "USB packet:", bytes


		limit_bytes = list(bytes)[0:2]
		self.previous_fire_state = limit_bytes[1] & (1 << 7)


		limit_signal = (limit_bytes[1] & 0x0F) | (limit_bytes[0] >> 6)

		new_limit_switch_states = [bool(limit_signal & (1 << i)) for i in range(4)]
		self.previous_limit_switch_states = new_limit_switch_states

		return new_limit_switch_states


# ============================================
# ============================================

class BlueRocketLauncher(OriginalRocketLauncher):

	color_green = False

	def __init__(self):
		OriginalRocketLauncher.__init__(self)

	# -----------------------------
	def start_movement(self, command_index):
		self.issue_command( command_index )

	# -----------------------------
	def stop_movement(self):
		self.issue_command( 5 )

	# -----------------------------
	def check_limits(self):

		'''For the "blue" rocket launcher, the firing bit is only toggled when the rocket fires, then
		is immediately reset.'''


		bytes = None
		self.issue_command( 6 )

		try:
			bytes = self.handle.bulkRead(1, 1)

		except usb.USBError, e:
			if e.message.find("No error") >= 0 \
			or e.message.find("could not claim interface") >= 0 \
			or e.message.find("Value too large") >= 0:

				pass
#				if self.usb_debug:
#					print "POLLING ERROR"

				# TODO: Should we try again in a loop?
			else:
				raise e


		if self.usb_debug:
			print "USB packet:", bytes

		self.previous_fire_state = bool(bytes)




		if bytes is None:
			return self.previous_limit_switch_states
		else:
			limit_signal, = bytes
			new_limit_switch_states = [bool(limit_signal & (1 << i)) for i in range(4)]

			self.previous_limit_switch_states = new_limit_switch_states
			return new_limit_switch_states



# ============================================
# ============================================

class BlackRocketLauncher(BlueRocketLauncher):

	striker_commands = [0xf, 0xe, 0xd, 0xc, 0xa, 0x14, 0xb]
	has_laser = True

	# -----------------------------
	def issue_command(self, command_index):

		signal = self.striker_commands[command_index]

		try:
			self.handle.controlMsg(0x21, 0x09, [signal, signal])

		except usb.USBError:
			pass

	# -----------------------------
	def check_limits(self):

		return self.previous_limit_switch_states



# ============================================
# ============================================

class GrayRocketLauncher(BlueRocketLauncher):

	striker_commands = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]
	has_laser = False

	# -----------------------------
	def issue_command(self, command_index):

		signal = self.striker_commands[command_index]

		try:
			self.handle.controlMsg(0x21,0x09, [0x02, signal, 0x00,0x00,0x00,0x00,0x00,0x00])

		except usb.USBError:
			pass

	# -----------------------------
	def check_limits(self):

		return self.previous_limit_switch_states


