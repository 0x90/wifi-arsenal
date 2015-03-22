import sys
import traceback

import netlink.capi as nl
import netlink.core as nlc
import netlink.genl.capi as genl
import generated.defs as nl80211

from generated.policy import nl80211_policy
from base import *

rate_policy = nl.nla_policy_array(nl80211.BITRATE_ATTR_MAX + 1)
rate_policy[nl80211.BITRATE_ATTR_RATE].type = nl.NLA_U32
rate_policy[nl80211.BITRATE_ATTR_2GHZ_SHORTPREAMBLE].type = nl.NLA_FLAG

class wiphy_rate(nl80211_object):
	policy = rate_policy
	max_attr = len(rate_policy)
	def __init__(self, attrs):
		nl80211_object.__init__(self, attrs, rate_policy)

freq_policy = nl.nla_policy_array(nl80211.FREQUENCY_ATTR_MAX + 1)
freq_policy[nl80211.FREQUENCY_ATTR_FREQ].type = nl.NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_DISABLED].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_IBSS].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_PASSIVE_SCAN].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_RADAR].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_MAX_TX_POWER].type = nl.NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_NO_HT40_MINUS].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_HT40_PLUS].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_80MHZ].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_160MHZ].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_DFS_STATE].type = nl.NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_DFS_TIME].type = nl.NLA_U32

class wiphy_freq(nl80211_object):
	policy = freq_policy
	max_attr = len(freq_policy)
	def __init__(self, attrs):
		nl80211_object.__init__(self, attrs, freq_policy)

band_policy = nl.nla_policy_array(nl80211.BAND_ATTR_MAX + 1)
band_policy[nl80211.BAND_ATTR_FREQS].type = nl.NLA_NESTED
band_policy[nl80211.BAND_ATTR_RATES].type = nl.NLA_NESTED
band_policy[nl80211.BAND_ATTR_HT_MCS_SET].type = nl.NLA_UNSPEC
band_policy[nl80211.BAND_ATTR_HT_CAPA].type = nl.NLA_U16
band_policy[nl80211.BAND_ATTR_HT_AMPDU_FACTOR].type = nl.NLA_U8
band_policy[nl80211.BAND_ATTR_HT_AMPDU_DENSITY].type = nl.NLA_U8
band_policy[nl80211.BAND_ATTR_VHT_MCS_SET].type = nl.NLA_UNSPEC
band_policy[nl80211.BAND_ATTR_VHT_CAPA].type = nl.NLA_U32

class wiphy_band(nl80211_object):
	nest_attr_map = {
		nl80211.BAND_ATTR_FREQS: wiphy_freq,
		nl80211.BAND_ATTR_RATES: wiphy_rate,
	}
	policy = band_policy
	max_attr = len(band_policy)
	def __init__(self, attrs):
		nl80211_object.__init__(self, attrs, band_policy)

class wiphy(nl80211_managed_object):
	nest_attr_map = {
		nl80211.ATTR_WIPHY_BANDS: wiphy_band,
	}
	_cmd = nl80211.CMD_GET_WIPHY
	def __init__(self, access, attrs):
		nl80211_managed_object.__init__(self, access, attrs, nl80211_policy)
		self._phynum = nl.nla_get_u32(attrs[nl80211.ATTR_WIPHY])

	def put_obj_id(self, msg):
		nl.nla_put_u32(msg._msg, nl80211.ATTR_WIPHY, self.phynum)

	@property
	def phynum(self):
		return self._phynum

	def __hash__(self):
		return self._phynum


class wiphy_list(ValidHandler):
	def __init__(self, kind=nl.NL_CB_DEFAULT):
		self._wiphy = {}
		a = access80211(kind)
		flags = nlc.NLM_F_REQUEST | nlc.NLM_F_ACK | nlc.NLM_F_DUMP
		m = a.alloc_genlmsg(nl80211.CMD_GET_WIPHY, flags)
		self._access = a
		a.send(m, self)

	def __iter__(self):
		return iter(self._wiphy.values())

	def handle(self, msg, arg):
		try:
			e, attrs = genl.py_genlmsg_parse(nl.nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			if nl80211.ATTR_WIPHY in attrs:
				phynum = nl.nla_get_u32(attrs[nl80211.ATTR_WIPHY])
				if phynum in self._wiphy.keys():
					self._wiphy[phynum].store_attrs(attrs)
				else:
					phy = wiphy(self._access, attrs)
					self._wiphy[phy.phynum] = phy
			return nl.NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)
