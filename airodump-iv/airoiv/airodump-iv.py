"""
airdump-iv is a utility which sniffs 802.11X activity

The goal of this script is to aggregate the functionality of tools like
airmon-ng and airodump-ng into a single easily extendable python tool.

Current functionality mimics airodump-ng for the most part.
"""
import curses
import errno
import sys
import traceback

from datetime import datetime
from optparse import OptionParser
from random import randint
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.layers.dot11 import Dot11ProbeResp
from scapy.layers.dot11 import RadioTap
import scapy_ex

from printer import Printer
from we import WirelessExtension

BROADCAST_BSSID = 'ff:ff:ff:ff:ff:ff'

class Dot11ScannerOptions:
	"""A collection of options to control how the script runs"""
	def __init__(self):
		self.iface = 'mon0'
		self.packet_count = 0
		self.channel = -1
		self.channel_hop = True
		self.max_channel = -1
		self.input_file = None
		self.enable_curses = True

	@staticmethod
	def create_scanner_options():
		"""A class factory which parses command line options and returns a Dot11ScannerOptions instance"""
		parser = OptionParser()
		parser.add_option('-i', '--iface', dest='iface', default='mon0',
						  help='Interface to bind to')
		parser.add_option('-c', '--channel', dest='channel', default=-1, type='int',
						  help='Channel to bind to')
		parser.add_option('--max-channel', dest='max_channel', default=-1, type='int',
						  help='Maximum channel number')
		parser.add_option('--packet_count', dest='packet_count', default=-1, type='int',
						  help='Number of packets to capture')
		parser.add_option('-r', '--input-file', dest='input_file', default=None,
						  help='Read packets from pcap file')
		parser.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
						  help='Print verbose information')
		parser.add_option('--verbose-level', dest='verbose_level', default=0, type='int',
						  help='Level of verbosity')
		parser.add_option('--no-curses', dest='no_curses', default=False, action='store_true',
		                  help='Do not enable curses display')
		options, _ = parser.parse_args()

		scanner_options = Dot11ScannerOptions()
		scanner_options.iface = options.iface
		scanner_options.we = WirelessExtension(scanner_options.iface)
		scanner_options.channel = options.channel
		scanner_options.channel_hop = (-1 == options.channel and not options.input_file)
		scanner_options.max_channel = options.max_channel
		if -1 == scanner_options.max_channel:
			if not options.input_file:
				try:
					scanner_options.max_channel = scanner_options.we.get_max_channel()
					Printer.verbose('CHAN: max_channel[{0}]'.format(scanner_options.max_channel), verbose_level=1)
				except Exception, e:
					Printer.exception(e)
					raise
			else:
				scanner_options.max_channel = 14

		scanner_options.packet_count = options.packet_count
		scanner_options.input_file = options.input_file
		scanner_options.enable_curses = not options.no_curses

		if options.verbose:
			options.verbose_level = 1
		Printer.verbose_level = options.verbose_level
		return scanner_options

class AccessPoint:
	"""Representation of an access point"""

	def __init__(self, packet):
		self.bssid = packet[Dot11].ap_bssid()
		self.beacon_count = 0
		self.data_count = 0
		self.sta_bssids = set()
		self.essid = ''
		self.channel = None
		self.enc = 'OPN'
		self.cipher = ''
		self.auth = ''
		self.hidden_essid = False
		self.power = 0
		self.max_rate = 0

		self.display_row = -1

	def update(self, packet):
		essid = packet[Dot11].essid()
		if essid:
			self.essid = essid

		self.channel = packet[Dot11].channel() or packet[RadioTap].Channel

		is_beacon = packet.haslayer(Dot11Beacon)
		is_probe_resp = packet.haslayer(Dot11ProbeResp)

		if is_beacon:
			self.beacon_count += 1
			self.hidden_essid = (not essid)

			if packet.hasflag('cap', 'privacy'):
				elt_rsn = packet[Dot11].rsn()
				if elt_rsn:
					Printer.write('Packets has RSN')
					self.enc = elt_rsn.enc
					self.cipher = elt_rsn.cipher
					self.auth = elt_rsn.auth
				else:
					self.enc = 'WEP'
					self.cipher = 'WEP'
					self.auth = ''
			else:
				self.enc = 'OPN'
				self.cipher = ''
				self.auth = ''

		elif is_probe_resp:
			self.sta_bssids.add(packet[Dot11].sta_bssid())

		if is_beacon or is_probe_resp:
			rates = packet[Dot11].rates()
			rates.extend(packet[Dot11].extended_rates())
			if rates:
				self.max_rate = max(rates)

		if self.bssid == packet[Dot11].addr2:
			power = packet[RadioTap].dBm_AntSignal
			if power:
				self.power = power

	def show(self, bssid_to_essid=None):
		if not self.essid and bssid_to_essid:
			self.essid = bssid_to_essid.get(self.bssid, self.essid)

		hidden = 'YES' if self.hidden_essid else 'NO'

		summary = '{0:<18} {1: >3d} {2: >5d} {3: >5d} {4: >2d} {5:<4} {6:<4} {7:<4} {8:<4} {9: >3} {10:<32} '.format(
			self.bssid,
			self.power,
			self.beacon_count,
			self.data_count,
			self.channel,
			self.max_rate,
			self.enc,
			self.cipher,
			self.auth,
			hidden,
			self.essid
		)
		#if len(self.sta_bssids):
		#	summary = '\n'.join([summary, '\t{0}'.format(' '.join(self.sta_bssids))])

		return summary


class Station:
	def __init__(self, bssid):
		self.bssid = bssid
		self.probes = {}
		self.auth_reqs = {}
		self.is_in_active_mode = False

	def _add_probe(self, packet):
		essid = packet[Dot11].essid()
		if essid in self.probes:
			self.probes[essid] += 1
		else:
			self.probes[essid] = 1

	def _add_auth_req(self, packet):
		ap_bssid = packet[Dot11].ap_bssid()
		if ap_bssid in self.auth_reqs:
			self.auth_reqs[ap_bssid] += 1
		else:
			self.auth_reqs[ap_bssid] = 1

	def update(self, packet):
		if packet.haslayer(Dot11ProbeReq):
			self._add_probe(packet)

		if packet.haslayer(Dot11Auth):
			self._add_auth_req(packet)

		if packet[Dot11].hasflag('FCfield', 'to-DS'):
			self.is_in_active_mode = packet[Dot11].hasflag('FCfield', 'pw-mgt')

	@staticmethod
	def _show_bssid(bssid, bssid_to_essid):
		if bssid_to_essid and bssid in bssid_to_essid:
			return '{0} ({1})'.format(bssid_to_essid[bssid], bssid)
		return bssid

	def show(self, bssid_to_essid=None):
		return 'STA {0:<18} probes:{1} auth_req:{2}'.format(self.bssid,
															repr(self.probes),
															repr([self._show_bssid(auth_req, bssid_to_essid) for auth_req in self.auth_reqs]))


class Dot11Scanner:

	def __init__(self, scanner_options):
		self.scanner_options = scanner_options
		self.access_points = dict()
		self.stations = dict()
		self.bssid_to_essid = dict()

	def _update_access_points(self, packet):
		show = False

		# Look for an ap or create one
		bssid = packet[Dot11].ap_bssid()
		if bssid == BROADCAST_BSSID:
			return None

		if bssid in self.access_points:
			ap = self.access_points[bssid]
		else:
			ap = self.access_points[bssid] = AccessPoint(packet)
			show = True
		ap.update(packet)

		self.bssid_to_essid[ap.bssid] = ap.essid

		if show:
			Printer.verbose(ap.show(bssid_to_essid=self.bssid_to_essid), verbose_level=1)

		return ap

	def _update_stations(self, packet):
		show = False

		bssid = packet[Dot11].sta_bssid()
		if bssid in self.stations:
			station = self.stations[bssid]
		else:
			station = self.stations[bssid] = Station(bssid)
			show = True
		station.update(packet)

		if show:
			Printer.verbose(station.show(), verbose_level=2)

		return station

	def _filter_function(self, packet):
		try:
			# Verify the RadioTap header, scanner, and WE all match
			# if packet.haslayer(RadioTap) and not self.scanner_options.input_file:
				# assert (self.scanner_options.channel == packet[RadioTap].Channel), 'got[{0}] expect[{1}]'.format(packet[RadioTap].Channel, self.scanner_options.channel)

				# channel = self.scanner_options.we.get_channel()
				# assert (self.scanner_options.channel == channel), 'got[{0}] expected[{1}]'.format(channel, self.scanner_options.channel)

			# Track AP and STA
			if packet.haslayer(Dot11):
				ap = None
				if packet.haslayer(Dot11Beacon):
					ap = self._update_access_points(packet)

				elif any(packet.haslayer(layer) for layer in [Dot11ProbeReq, Dot11ProbeResp, Dot11Auth]):
					ap = self._update_access_points(packet)
					self._update_stations(packet)

				elif packet[Dot11].hasflag('type', 'Data'):
					ap_bssid = packet[Dot11].ap_bssid()
					if ap_bssid in self.access_points:
						self.access_points[ap_bssid].data_count += 1

				if self.display and ap:
					self.display.update(ap)

				return True

			# That's unexpected.  print for debugging
			else:
				Printer.error(packet.show())
		except Exception, exc:
			Printer.exception(exc)
		finally:
			return False

	def scan(self, window = None):
		if window:
			self.display = Display(window, self)
		else:
			self.display = None

		if not self.scanner_options.input_file:
			timeout = 5
		else:
			timeout = None

		if self.scanner_options.channel_hop:
			self.scanner_options.channel = randint(1, self.scanner_options.max_channel)
			self.set_channel(self.scanner_options.channel)
		elif -1 != self.scanner_options.channel:
			self.set_channel(self.scanner_options.channel)

		while True:
			try:
				sniff(iface=self.scanner_options.iface,
					  store=False,
					  count=self.scanner_options.packet_count,
					  offline=self.scanner_options.input_file,
					  timeout=timeout,
					  lfilter=self._filter_function)
				if timeout:
					try:
						ch = self.display.window.getkey()
						if 'q' == ch:
							break
					except:
						pass

					if self.display:
						self.display.update_header()

					if self.scanner_options.channel_hop:
						self.scanner_options.channel = ((self.scanner_options.channel + 3) % self.scanner_options.max_channel) + 1
						self.set_channel(self.scanner_options.channel)
				else:
					break

			# Exit the scan on a keyboard break
			except KeyboardInterrupt:
				break

			# Curses generates system interupt exception (EINTR) when the window is resized
			except Exception, e:
				if e.args and e.args[0] == errno.EINTR:
					pass
				else:
					Printer.exception(e)
					raise

	def set_channel(self, channel):
		Printer.verbose('CHAN: set_channel {0}'.format(channel), verbose_level=3)
		try:
			self.scanner_options.we.set_channel(channel)
		except Exception, e:
			Printer.exception(e)

		if self.display:
			self.display.update_header()

	def print_results(self):
		Printer.write('\n\n')
		Printer.write('{0:<18} {1:>3} {2:5} {3:5} {4:2} {5:<4} {6:<4} {7:<4} {8:<4} {9:3} {10:<32}'.format('BSSID', 'PWR', '#BEAC', '#DATA', 'CH', 'MB', 'ENC', 'CIPH', 'AUTH', 'HID', 'ESSID'))
		for access_point in self.access_points.values():
			Printer.write(access_point.show(bssid_to_essid=self.bssid_to_essid))

		for bssid, station in self.stations.iteritems():
			if len(station.probes) or len(station.auth_reqs):
				Printer.write(station.show(bssid_to_essid=self.bssid_to_essid))

class Display:
	def __init__(self, window, scanner):
		self.window = window
		self.scanner = scanner
		self.free_row = 2
		self.start_time = datetime.now()

		curses.use_default_colors()

		# not all terminals offer curs_set to adjust cursor visibility
		try:
			self.window.curs_set(0)
		except:
			try:
				self.window.curs_set(1)
			except:
				pass

		self.window.nodelay(1)
		self.window.clear()
		header = '{0:<18} {1:>3} {2:5} {3:5} {4:2} {5:<4} {6:<4} {7:<4} {8:<4} {9:3} {10:<32}'.format('BSSID', 'PWR', '#BEAC', '#DATA', 'CH', 'MB', 'ENC', 'CIPH', 'AUTH', 'HID', 'ESSID')
		self._addstr(self.free_row, header)
		self.free_row += 2
		self.update_header()


	def _addstr(self, row, msg):
		self.window.addstr(row, 0, msg)
		self.window.clrtoeol()
		self.window.move(0,0)


	def _seconds_elapsed(self):
		time_delta = datetime.now() - self.start_time
		return (time_delta.microseconds + (time_delta.seconds + time_delta.days * 24 * 3600) * 10**6) / 10**6


	def _update_header(self):
		header = ' CH {0:>2d}][ Elapsed {1:d}s][ {2:s}'.format(
			self.scanner.scanner_options.channel,
			self._seconds_elapsed(),
		    datetime.now().strftime('%x %X'))
		self._addstr(0, header)


	def update_header(self):
		self._update_header()
		self.window.refresh()


	def update(self, access_point):

		# TODO(ivanlei) - When the # of rows exceeds the height of the window, this throws exceptions
		if -1 == access_point.display_row:
			access_point.display_row = self.free_row
			self.free_row += 1

		# Update a full line and don't leave the cursor at the end of the line
		self._addstr(access_point.display_row, access_point.show(bssid_to_essid=self.scanner.bssid_to_essid))

		# Update Headers
		self.update_header()

		# Repaint
		self.window.refresh()


def main():

	try:
		scanner_options = Dot11ScannerOptions.create_scanner_options()
		scanner = Dot11Scanner(scanner_options)

		try:
			if scanner_options.enable_curses:
				curses.wrapper(scanner.scan)
			else:
				scanner.scan()
		except Exception, e:
			Printer.exception(e)

		# Run with or without curses support, but finish in either case by printing a complete report
		if scanner:
			scanner.print_results()

	except Exception, e:
		sys.stderr.write(repr(e))
		traceback.print_exc(file=sys.stderr)


if __name__ == '__main__':
	main()

