"""
A set of additions and modifications to scapy to assist in parsing dot11
"""
import scapy

from scapy.fields import BitField
from scapy.fields import ByteField
from scapy.fields import ConditionalField
from scapy.fields import EnumField
from scapy.fields import Field
from scapy.fields import FieldLenField
from scapy.fields import FieldListField
from scapy.fields import FlagsField
from scapy.fields import LEFieldLenField
from scapy.fields import LELongField
from scapy.fields import LEShortField
from scapy.fields import StrFixedLenField
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.packet import Packet

from printer import Printer


class SignedByteField(Field):
	"""Fields for a signed byte"""
	def __init__(self, name, default):
		Field.__init__(self, name, default, '<b')


class LESignedShortField(Field):
	"""Field for a little-endian short"""
	def __init__(self, name, default):
		Field.__init__(self, name, default, '<h')


def scapy_packet_Packet_hasflag(self, field_name, value):
	"""Is the specified flag value set in the named field"""
	field, val = self.getfield_and_val(field_name)
	if isinstance(field, EnumField):
		if val not in field.i2s:
			return False
		return field.i2s[val] == value
	else:
		return (1 << field.names.index([value])) & self.__getattr__(field_name) != 0
scapy.packet.Packet.hasflag = scapy_packet_Packet_hasflag
del scapy_packet_Packet_hasflag


def scapy_fields_FieldListField_i2repr(self, pkt, x):
	"""Return a list with the representation of contained fields"""
	return repr([self.field.i2repr(pkt, v) for v in x])
FieldListField.i2repr = scapy_fields_FieldListField_i2repr
del scapy_fields_FieldListField_i2repr


class ChannelFromMhzField(LEShortField):
	"""A little-endian short field that converts from mhz to channel"""
	def m2i(self, pkt, x):
		return min(14, max(1, (x - 2407) / 5))


class PresentFlagField(ConditionalField):
	"""Utility field for use by RadioTap"""
	def __init__(self, field, flag_name):
		ConditionalField.__init__(self, field, lambda pkt: pkt.hasflag('present', flag_name))


# TODO(ivanlei): This fields_desc does not cover chained present flags decode will fail in this cases
scapy.layers.dot11.RadioTap.name = '802.11 RadioTap'

# Greatly improved fields_desc for RadioTap which parses known present flags
scapy.layers.dot11.RadioTap.fields_desc = [
	ByteField('version', 0),
	ByteField('pad', 0),
	LEShortField('RadioTap_len', 0),
	FlagsField('present', None, -32, ['TSFT','Flags','Rate','Channel','FHSS','dBm_AntSignal',
									  'dBm_AntNoise','Lock_Quality','TX_Attenuation','dB_TX_Attenuation',
									  'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',
									  'b14', 'b15','b16','b17','b18','b19','b20','b21','b22','b23',
									  'b24','b25','b26','b27','b28','b29','b30','Ext']),
	PresentFlagField(LELongField('TSFT', 0), 'TSFT'),
	PresentFlagField(ByteField('Flags', 0), 'Flags'),
	PresentFlagField(ByteField('Rate', 0), 'Rate'),
	PresentFlagField(ChannelFromMhzField('Channel', 0), 'Channel'),
	PresentFlagField(LEShortField('Channel_flags', 0), 'Channel'),
	PresentFlagField(ByteField('FHSS_hop_set', 0), 'FHSS'),
	PresentFlagField(ByteField('FHSS_hop_pattern', 0), 'FHSS'),
	PresentFlagField(SignedByteField('dBm_AntSignal', 0), 'dBm_AntSignal'),
	PresentFlagField(SignedByteField('dBm_AntNoise', 0), 'dBm_AntNoise'),
	PresentFlagField(LEShortField('Lock_Quality', 0), 'Lock_Quality'),
	PresentFlagField(LEShortField('TX_Attenuation', 0), 'TX_Attenuation'),
	PresentFlagField(LEShortField('db_TX_Attenuation', 0), 'dB_TX_Attenuation'),
	PresentFlagField(SignedByteField('dBm_TX_Power', 0), 'dBm_TX_Power'),
	PresentFlagField(ByteField('Antenna', 0), 'Antenna'),
	PresentFlagField(ByteField('dB_AntSignal', 0), 'dB_AntSignal'),
	PresentFlagField(ByteField('dB_AntNoise', 0), 'dB_AntNoise'),
	PresentFlagField(LEShortField('RX_Flags', 0), 'b14')
]


def scapy_layers_dot11_RadioTap_extract_padding(self, s):
	"""Ignore any unparsed conditionally present fields

	If all fields have been parsed, the payload length should have decreased RadioTap_len bytes
	If it has not, there are unparsed fields which should be treated as padding
	"""
	padding = len(s) - (self.pre_dissect_len - self.RadioTap_len)
	if padding:
		return s[padding:], s[:padding]
	else:
		return s, None
scapy.layers.dot11.RadioTap.extract_padding = scapy_layers_dot11_RadioTap_extract_padding
del scapy_layers_dot11_RadioTap_extract_padding


def scapy_layers_dot11_RadioTap_pre_dissect(self, s):
	"""Cache to total payload length prior to dissection for use in finding padding latter"""
	self.pre_dissect_len = len(s)
	return s
scapy.layers.dot11.RadioTap.pre_dissect = scapy_layers_dot11_RadioTap_pre_dissect
del scapy_layers_dot11_RadioTap_pre_dissect


class Dot11EltRates(Packet):
	"""The rates member contains an array of supported rates"""

	name = '802.11 Rates Information Element'

	# Known rates come from table in 6.5.5.2 of the 802.11 spec
	known_rates = {
		  2 :  1,
		  3 :  1.5,
		  4 :  2,
		  5 :  2.5,
		  6 :  3,
		  9 :  4.5,
		 11 :  5.5,
		 12 :  6,
		 18 :  9,
		 22 : 11,
		 24 : 12,
		 27 : 13.5,
		 36 : 18,
		 44 : 22,
		 48 : 24,
		 54 : 27,
		 66 : 33,
		 72 : 36,
		 96 : 48,
		108 : 54
	}

	fields_desc = [
		ByteField('ID', 0),
		FieldLenField("len", None, "info", "B"),
		FieldListField('supported_rates', None, ByteField('', 0), count_from=lambda pkt: pkt.len),
	]

	def post_dissection(self, pkt):
		self.rates = []
		for supported_rate in self.supported_rates:
			# check the msb for each rate
			rate_msb = supported_rate & 0x80
			rate_value = supported_rate & 0x7F
			if rate_msb:
				# a value of 127 means HT PHY feature is required to join the BSS
				if 127 != rate_value:
					self.rates.append(rate_value/2)
			elif rate_value in Dot11EltRates.known_rates:
				self.rates.append(Dot11EltRates.known_rates[rate_value])


class Dot11EltExtendedRates(Dot11EltRates):
	"""The rates member contains an additional array of supported rates"""

	name = '802.11 Extended Rates Information Element'


class Dot11EltRSN(Packet):
	"""The enc, cipher, and auth members contain the decoded 'security' details"""

	name = '802.11 RSN Information Element'

	cipher_suites = { '\x00\x0f\xac\x00': 'GROUP',
					  '\x00\x0f\xac\x01': 'WEP',
					  '\x00\x0f\xac\x02': 'TKIP',
					  '\x00\x0f\xac\x04': 'CCMP',
					  '\x00\x0f\xac\x05': 'WEP' }

	auth_suites = { '\x00\x0f\xac\x01': 'MGT',
					'\x00\x0f\xac\x02': 'PSK' }

	fields_desc = [
		ByteField('ID', 0),
		FieldLenField("len", None, "info", "B"),
		LEShortField('version', 1),
		StrFixedLenField('group_cipher_suite', '', length=4),
		LEFieldLenField('pairwise_cipher_suite_count', 1, count_of='pairwise_cipher_suite'),
		FieldListField('pairwise_cipher_suite', None, StrFixedLenField('','', length=4), count_from=lambda pkt: pkt.pairwise_cipher_suite_count),
		LEFieldLenField('auth_cipher_suite_count', 1, count_of='auth_cipher_suite'),
		FieldListField('auth_cipher_suite', None, StrFixedLenField('','',length=4), count_from=lambda pkt: pkt.auth_cipher_suite_count),
		BitField('rsn_cap_pre_auth', 0, 1),
		BitField('rsn_cap_no_pairwise', 0, 1),
		BitField('rsn_cap_ptksa_replay_counter', 0, 2),
		BitField('rsn_cap_gtksa_replay_counter', 0, 2),
		BitField('rsn_cap_mgmt_frame_protect_required', 0, 1),
		BitField('rsn_cap_mgmt_frame_protect_capable', 0, 1),
		BitField('rsn_cap_reserved_1', 0, 1),
		BitField('rsn_cap_peer_key_enabled', 0, 1),
		BitField('rsn_cap_reserved_2', 0, 6),
	]

	def post_dissection(self, pkt):
		"""Parse cipher suites to determine encryption, cipher, and authentication methods"""

		self.enc = 'WPA2' # Everything is assumed to be WPA
		self.cipher = ''
		self.auth = ''

		ciphers = [self.cipher_suites.get(pairwise_cipher) for pairwise_cipher in self.getfieldval('pairwise_cipher_suite')]
		if 'GROUP' in ciphers:
			ciphers = [self.cipher_suites.get(group_cipher, '') for group_cipher in self.getfieldval('group_cipher_suite')]
		for cipher in ['CCMP', 'TKIP', 'WEP']:
			if cipher in ciphers:
				self.cipher = cipher
				break

		if 'WEP' == self.cipher:
			self.enc = 'WEP'

		for auth_cipher in self.getfieldval('auth_cipher_suite'):
			self.auth = self.auth_suites.get(auth_cipher, '')
			break


def scapy_layers_dot11_Dot11_elts(self):
	"""An iterator of Dot11Elt"""
	dot11elt = self.getlayer(Dot11Elt)
	while dot11elt and dot11elt.haslayer(Dot11Elt):
		yield dot11elt
		dot11elt = dot11elt.payload
scapy.layers.dot11.Dot11.elts = scapy_layers_dot11_Dot11_elts
del scapy_layers_dot11_Dot11_elts


def scapy_layers_dot11_Dot11_find_elt_by_id(self, id):
	"""Iterate over elt and return the first with a specific ID"""
	for elt in self.elts():
		if elt.ID == id:
			return elt
	return None
scapy.layers.dot11.Dot11.find_elt_by_id = scapy_layers_dot11_Dot11_find_elt_by_id
del scapy_layers_dot11_Dot11_find_elt_by_id


def scapy_layers_dot11_Dot11_essid(self):
	"""Return the payload of the SSID Dot11Elt if it exists"""
	elt = self.find_elt_by_id(0)
	return elt.info if elt else None
scapy.layers.dot11.Dot11.essid = scapy_layers_dot11_Dot11_essid
del scapy_layers_dot11_Dot11_essid


def scapy_layers_dot11_Dot11_rates(self, id=1):
	"""Return the payload of the rates Dot11Elt if it exists"""
	elt = self.find_elt_by_id(id)
	if elt:
		try:
			return Dot11EltRates(str(elt)).rates
		except Exception, e:
			Printer.error('Bad Dot11EltRates got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return []
scapy.layers.dot11.Dot11.rates = scapy_layers_dot11_Dot11_rates
del scapy_layers_dot11_Dot11_rates


def scapy_layers_dot11_Dot11_extended_rates(self):
	"""Return the payload of the extended rates Dot11Elt if it exists"""
	return scapy.layers.dot11.Dot11.rates(self, 50)
scapy.layers.dot11.Dot11.extended_rates = scapy_layers_dot11_Dot11_extended_rates
del scapy_layers_dot11_Dot11_extended_rates


def scapy_layers_dot11_Dot11_sta_bssid(self):
	"""Return the bssid for a station associated with the packet"""
	if self.haslayer(Dot11ProbeReq) or self.hasflag('FCfield', 'to-DS'):
		return self.addr2
	else:
		return self.addr1
scapy.layers.dot11.Dot11.sta_bssid = scapy_layers_dot11_Dot11_sta_bssid
del scapy_layers_dot11_Dot11_sta_bssid


def scapy_layers_dot11_Dot11_ap_bssid(self):
	"""Return the bssid for a access point associated with the packet"""
	if self.haslayer(Dot11ProbeReq) or self.hasflag('FCfield', 'to-DS'):
		return self.addr1
	else:
		return self.addr2
scapy.layers.dot11.Dot11.ap_bssid = scapy_layers_dot11_Dot11_ap_bssid
del scapy_layers_dot11_Dot11_ap_bssid


def scapy_layers_dot11_Dot11_channel(self):
	"""Return the payload of the channel Dot11Elt if it exists"""
	elt = self.find_elt_by_id(3)
	if elt:
		try:
			return int(ord(elt.info))
		except Exception, e:
			Printer.error('Bad Dot11Elt channel got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return None
scapy.layers.dot11.Dot11.channel = scapy_layers_dot11_Dot11_channel
del scapy_layers_dot11_Dot11_channel


def scapy_layers_dot11_Dot11_rsn(self):
	"""Return the payload of the RSN Dot11Elt as a Dot11EltRSN"""
	elt = self.find_elt_by_id(48)
	if elt:
		try:
			return Dot11EltRSN(str(elt))
		except Exception, e:
			Printer.error('Bad Dot11EltRSN got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return None
scapy.layers.dot11.Dot11.rsn = scapy_layers_dot11_Dot11_rsn
del scapy_layers_dot11_Dot11_rsn
