import py80211.generated.defs as nl80211
from py80211 import wiphy

def bitfield2str(label, value, size, spec):
	"""
	 print bitfield values according provided bitfield
	 specification. This specification contains multiple
	 entries characterizing a bitfield:
	 - start: starting bit position of the bitfield.
	 - length: number of bits for this bitfield.
	 - name: bitfield identifier.
	 - description: long description of bitfield.
	 - conv: conversion function to use for this bitfield.
	"""
	s = '%s: 0x%0*x\n' % (label, size >> 2, value)
	for (start, length, name, description, conv) in spec:
		field = (value >> start) & ((1 << length) - 1)
		if conv != None:
			s += "	%-15s %12s (%s)\n" % (name, conv(field), description)
		elif field != 0 or length > 1:
			s += "	%-15s %#12x (%s)\n" % (name, field, description)
	return s

class wiphy_rate_info(object):
	def __init__(self, rate):
		self._rate = rate

	def __str__(self):
		s = '%3.1f' % (0.1 * self._rate.attrs[nl80211.BITRATE_ATTR_RATE])
		if nl80211.BITRATE_ATTR_2GHZ_SHORTPREAMBLE in self._rate.attrs:
			s += ' (short)'
		return s

class wiphy_freq_info(object):
	def __init__(self, freq):
		self._freq = freq

	@property
	def channel(self):
		freq = self._freq.attrs[nl80211.FREQUENCY_ATTR_FREQ]
		# see 802.11 17.3.8.3.2 and Annex J
		if freq == 2484:
			return 14
		elif freq < 2484:
			return (freq - 2407) / 5
		elif freq >= 4910 and freq <= 4980:
			return (freq - 4000) / 5
		elif freq <= 45000:
			# DMG band lower limit
			return (freq - 5000) / 5
		elif freq >= 58320 and freq <= 64800:
			return (freq - 56160) / 2160
		else:
			raise Exception('invalid channel frequency: %d' % freq)

	def __str__(self):
		s = '%6d MHz (%d)' % (self._freq.attrs[nl80211.FREQUENCY_ATTR_FREQ], self.channel)
		if nl80211.FREQUENCY_ATTR_DISABLED in self._freq.attrs:
			s += ' (disabled)'
			return s
		s += ' [%.2f dBm]' % (0.01 * self._freq.attrs[nl80211.FREQUENCY_ATTR_MAX_TX_POWER])
		return s

def smps2str(val):
	return [ 'static', 'dynamic', '[reserved]', 'disabled' ][val]

def stbc2str(val):
	if val == 0:
		return 'unsupported'
	else:
		return 'up to %d streams' % val

def amsdu2str(val):
	return [ '3839', '7935' ][val]

htcapinfo_fields = [
	[ 0, 1, 'LDPC', 'LDPC Coding Capability', None ],
	[ 1, 1, 'ChanWidth', 'Supported Channel Width Set', None ],
	[ 2, 2, 'SM-PS', 'SM PowerSave', smps2str ],
	[ 4, 1, 'HT-GF', 'HT-Greenfield', None ],
	[ 5, 1, 'SGI20', 'Short GI for 20MHz', None ],
	[ 6, 1, 'SGI40', 'Short GI for 40MHz', None ],
	[ 7, 1, 'TxSTBC', 'Transmit STBC', None ],
	[ 8, 2, 'RxSTBC', 'Receive STBC', stbc2str ],
	[ 10, 1, 'HT-DBA', 'HT-Delayed BlockAck', None ],
	[ 11, 1, 'A-MSDU', 'Maximum A-MSDU Length', amsdu2str ],
	[ 12, 1, 'DSSS/CCK', 'DSSS/CCK Mode in 40MHz', None ],
	[ 14, 1, 'FortyMHZ', 'Forty MHz Intolerant', None ],
	[ 15, 1, 'LSIG-Prot', 'L-SIG TXOP Protection', None ]
]

class wiphy_band_info(object):
	def __init__(self, band):
		self._band = band

	def __str__(self):
		s = ''
		if nl80211.BAND_ATTR_HT_CAPA in self._band.attrs:
			s += bitfield2str('HT Capabilities', self._band.attrs[nl80211.BAND_ATTR_HT_CAPA], 16, htcapinfo_fields)
		if nl80211.BAND_ATTR_VHT_CAPA in self._band.attrs:
			s += 'vht capability 0x%08x\n' % self._band.attrs[nl80211.BAND_ATTR_HT_CAPA]
		s += 'channels:\n'
		for f in self._band.attrs[nl80211.BAND_ATTR_FREQS]:
			s += '\t%s\n' % str(wiphy_freq_info(f))
		s += 'legacy rates:\n'
		for r in self._band.attrs[nl80211.BAND_ATTR_RATES]:
			s += '\t%s\n' % str(wiphy_rate_info(r))
		return s

class wiphy_info(object):
	def __init__(self, phy):
		self._wiphy = phy

	def __str__(self):
		"phy%d" % self._wiphy.phynum
