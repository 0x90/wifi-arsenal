"""
Utilities for using Wireless Extensions (WE) ioctls
  WT -- http://www.hpl.hp.com/personal/Jean_Tourrilhes/Linux/Tools.html
  WE -- /usr/include/linux/wireless.h

As set of scapy Packet classes model the structs from wireless.h
"""
import re
import socket
import sys


from ctypes import cast
from ctypes import c_int
from ctypes import c_uint
from ctypes import c_byte
from ctypes import c_ubyte
from ctypes import c_short
from ctypes import c_ushort
from ctypes import c_void_p
from ctypes import c_char
from ctypes import Structure
from ctypes import sizeof
from ctypes import pointer
from ctypes import Union
from exceptions import IOError
from fcntl import ioctl
from subprocess import check_call
from tempfile import SpooledTemporaryFile


class IW_PARAM(Structure):
	_fields_ = [('value', c_int),
				('fixed', c_byte),
				('disabled', c_byte),
				('flags', c_ushort)]


class IW_POINT(Structure):
	_fields_ = [('pointer', c_void_p),
				('length', c_ushort),
				('flags', c_ushort)]


class IW_QUALITY(Structure):
	_fields_ = [('qual', c_byte),
				('level', c_byte),
				('noise', c_byte),
				('updated', c_byte)]


class IW_FREQ(Structure):
	_fields_ = [('m', c_int),
				('e', c_short),
				('i', c_ubyte),
				('flags', c_byte)]


class IW_RANGE(Structure):
	_fields_ = [('throughput', c_uint),
				('min_nwid', c_uint),
				('max_nwid', c_uint),
				('old_num_channels', c_ushort),
				('old_num_frequency', c_byte),
				('scan_capa', c_byte),
				('event_capa', c_uint * 6),
				('sensitivity', c_int),
				('max_qual', IW_QUALITY),
				('avg_qual', IW_QUALITY),
				('num_bitrates', c_byte),
				('bitrate', c_int * 32),
				('min_rts', c_int),
				('max_rts', c_int),
				('min_frag', c_int),
				('max_frag', c_int),
				('min_pmp', c_int),
				('max_pmp', c_int),
				('min_pmt', c_int),
				('max_pmt', c_int),
				('pmp_flags', c_ushort),
				('pmt_flags', c_ushort),
				('pm_capa', c_ushort),
				('encoding_size', c_ushort * 8),
				('num_encoding_sizes', c_byte),
				('max_encoding_tokens', c_byte),
				('encoding_login_index', c_byte),
				('txpower_capa', c_ushort),
				('num_txpower', c_byte),
				('txpower', c_int * 8),
				('we_version_compiled', c_byte),
				('we_version_source', c_byte),
				('retry_capa', c_ushort),
				('retry_flags', c_ushort),
				('r_time_flags', c_ushort),
				('min_retry', c_int ),
				('max_retry', c_int ),
				('min_r_time', c_int ),
				('max_r_time', c_int),
				('num_channels', c_ushort),
				('num_frequency', c_byte),
				('freq', IW_FREQ * 32),
				('enc_capa', c_uint)]


class SOCKADDR(Structure):
	_fields_ = [('sa_family', c_ushort),
				('ss_data', c_char * 14)]


class IWREQ_DATA(Union):
	_fields_ = [('name', c_char * 16),
				('essid', IW_POINT),
				('nwid', IW_PARAM),
				('freq', IW_FREQ),
				('sens', IW_PARAM),
				('bitrate', IW_PARAM),
				('txpower', IW_PARAM),
				('rts', IW_PARAM),
				('frag', IW_PARAM),
				('mode', c_uint),
				('retry', IW_PARAM),
				('encoding', IW_PARAM),
				('power', IW_PARAM),
				('qual', IW_QUALITY),
				('ap_addr', SOCKADDR),
				('addr', SOCKADDR),
				('param', IW_PARAM),
				('data', IW_POINT)]

class IFR_IFRN(Union):
	_fields_ = [('ifr_name', c_char * 16)]


class IW_REQ(Structure):
	_fields_ = [('ifr_ifrn', IFR_IFRN),
				('iwreq_data', IWREQ_DATA)]


class WirelessIOCTL:
	# IOCTL to set channel/frequency (Hz)
	SIOCSIWFREQ = 0x8B04
	# IOCTL to get channel/frequency (Hz)
	SIOCGIWFREQ = 0x8B05
	# IOCTL to get range of parameters
	SIOCGIWRANGE = 0x8B0B

class WirelessExtension:
	"""A singleton for getting/caching/setting data with WE IOCTLS"""

	def __init__(self, iface):
		# Dict to map [channel -> iw_freq]
		self._freq_map = None

		# Maximum available channel
		self._max_channel = 0

		self._iface = iface

		self._can_ioctl_set_channel = True
		self._can_ioctl_get_channel = True
		self._can_ioctl_freq_map = True


	def _shell_command(self, cmd):
		"""Shell out a subprocess and return what it writes to stdout as a string"""
		in_mem_file = SpooledTemporaryFile(max_size=2048, mode="r+")
		check_call(cmd, shell=True, stdout=in_mem_file)
		in_mem_file.seek(0)
		stdout = in_mem_file.read()
		in_mem_file.close()
		return stdout


	def _ioctl(self, code, data, write_on_out=1):
		sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ioctl(sockfd.fileno(), code, data, write_on_out)
		sockfd.close()
		del sockfd


	def _ioctl_get_freq_map(self):
		"""Populate an iw_range with data and introspect the frequency data"""
		if self._freq_map:
			return self._freq_map

		if self._can_ioctl_freq_map:
			try:
				req = IW_REQ()
				req.ifr_ifrn.ifr_name = self._iface

				# Allocate an array for the response
				resp = IW_RANGE()
				resp.num_frequency = 0
				req.iwreq_data.data.pointer = cast(pointer(resp), c_void_p)
				req.iwreq_data.data.length = sizeof(resp)

				self._ioctl(WirelessIOCTL.SIOCGIWRANGE, req)

				self._freq_map = {}
				for index, freq in enumerate(resp.freq):
					if index >= resp.num_frequency:
						break
					if freq.m:
						self._freq_map[str(freq.i)] = freq
						if freq.i > self._max_channel:
							self._max_channel = freq.i
			except IOError:
				self._can_ioctl_freq_map = False

		if not self._can_ioctl_freq_map:
			stdout = self._shell_command('iwlist {0} frequency'.format(self._iface))
			match = re.search('(\d+) channels in total', stdout)
			self._max_channel = repr(match)

			self._freq_map = {}
			match = re.findall('Channel (\d+) : (\d+).?(\d+)?', stdout)
			for channel_id, freq_lead, freq_trail in match:
				freq = IW_FREQ(i=int(channel_id), m=int(freq_lead + freq_trail), e=7)
				self._freq_map[str(freq.i)] = freq

		return self._freq_map


	def get_max_channel(self):
		"""Get the maximum channel supported by the interface"""
		self._ioctl_get_freq_map()
		return self._max_channel


	def get_channel(self):
		"""Get the current channel for the interface"""
		channel = 0

		if self._can_ioctl_set_channel:
			req = IW_REQ()
			req.ifr_ifrn.ifr_name = self._iface
			try:
				self._ioctl(WirelessIOCTL.SIOCGIWFREQ, req)
				freq = req.iwreq_data.freq.m
				# TODO(ivanlei): Replace with more correct algorithm
				channel = min(14, max(1, (freq - 2407) / 5))

			except IOError:
				self._can_ioctl_get_channel = True

		if not self._can_ioctl_get_channel:
			stdout = self._shell_command('iwgetid -c {0}'.format(self._iface))
			match = re.search('Channel:(\d+)', stdout)
			channel = int(match.group(1))

		return channel


	def set_channel(self, channel):
		"""Set the current channel for the interface"""
		if self._can_ioctl_set_channel:
			self._ioctl_get_freq_map()
			freq = self._freq_map[str(channel)]

			req = IW_REQ()
			req.ifr_ifrn.ifr_name = self._iface
			req.iwreq_data.freq.m = freq.m
			req.iwreq_data.freq.e = freq.e
			req.iwreq_data.freq.i = freq.i
			req.iwreq_data.freq.flags = freq.flags

			try:
				self._ioctl(WirelessIOCTL.SIOCSIWFREQ,
							req,
							write_on_out=1)
			except IOError:
				self._can_ioctl_set_channel = False

		if not self._can_ioctl_set_channel:
			self._shell_command('iwconfig {0} channel {1}'.format(self._iface, channel))

