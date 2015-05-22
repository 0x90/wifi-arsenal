import sys
import traceback
from abc import *

import netlink.capi as nl
import netlink.genl.capi as genl
import netlink.core as nlc
import generated.defs as nl80211
from generated import strmap

NLA_NUL_STRING = nl.NLA_NESTED + 2
NLA_BINARY = nl.NLA_NESTED + 3

from abc import *

class AccessBusyError(Exception):
	pass

class ValidHandler(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def handle(self, msg, arg):
		pass

class access80211(object):
	""" provide access to the nl80211 API """
	def __init__(self, level=nl.NL_CB_DEFAULT):
		self._tx_cb = nlc.Callback(level)
		self._rx_cb = nlc.Callback(level)
		self._sock = nlc.Socket(self._tx_cb)

		self._rx_cb.set_err(nl.NL_CB_CUSTOM, self.error_handler, None)
		self._rx_cb.set_type(nl.NL_CB_FINISH, nl.NL_CB_CUSTOM, self.finish_handler, None)
		self._rx_cb.set_type(nl.NL_CB_ACK, nl.NL_CB_CUSTOM, self.ack_handler, None)

		self._sock.connect(nlc.NETLINK_GENERIC)
		self._family = genl.genl_ctrl_resolve(self._sock._sock, 'nl80211')
		self.busy = 0

	def alloc_genlmsg(self, cmd, flags=0):
		msg = nlc.Message()
		genl.genlmsg_put(msg._msg, 0, 0, self._family, 0, flags, cmd, 0)
		return msg

	def send(self, msg, handler):
		if not isinstance(handler, ValidHandler):
			raise Exception("provided 'handler' is not a ValidHandler instance")
		if self.busy == 1:
			raise AccessBusyError()
		self.busy = 1
		self._rx_cb.set_type(nl.NL_CB_VALID, nl.NL_CB_CUSTOM, handler.handle, None)
		err = self._sock.send_auto_complete(msg)
		while self.busy > 0 and not err < 0:
			self._sock.recvmsgs(self._rx_cb)
		return err

	@property
	def family(self):
		""" generic netlink family """
		return self._family

	def finish_handler(self, m, a):
		self.busy = 0
		return nl.NL_SKIP

	def ack_handler(self, m, a):
		self.busy = 0
		return nl.NL_STOP

	def error_handler(self, err, a):
		self.busy = err.error
		return nl.NL_STOP

class nl80211_object(object):
	def __init__(self, attrs, policy=None):
		self._attrs = {}
		self._policy = policy
		self.store_attrs(attrs)

	def store_nested(self, attr, aid):
		nest_class = None
		if aid in self.nest_attr_map.keys():
			nest_class = self.nest_attr_map[aid]
		self._attrs[aid] = []
		for nest_element in nl.nla_get_nested(attr):
			if nest_class == None:
				self._attrs[aid].append(nl.nla_type(nest_element))
			else:
				e, nattr = nl.py_nla_parse_nested(nest_class.max_attr, nest_element, nest_class.policy)
				self._attrs[aid].append(nest_class(nattr))

	def store_attrs(self, attrs):
		for attr in attrs.keys():
			try:
				pol = self._policy[attr]
				if pol.type == NLA_NUL_STRING:
					self._attrs[attr] = nl.nla_get_string(attrs[attr])
				elif pol.type == nl.NLA_U64:
					self._attrs[attr] = nl.nla_get_u64(attrs[attr])
				elif pol.type == nl.NLA_U32:
					self._attrs[attr] = nl.nla_get_u32(attrs[attr])
				elif pol.type == nl.NLA_U16:
					self._attrs[attr] = nl.nla_get_u16(attrs[attr])
				elif pol.type == nl.NLA_U8:
					self._attrs[attr] = nl.nla_get_u8(attrs[attr])
				elif pol.type == nl.NLA_FLAG:
					self._attrs[attr] = True
				elif pol.type == nl.NLA_NESTED:
					self.store_nested(attrs[attr], attr)
				elif pol.type in [ NLA_BINARY, nl.NLA_UNSPEC ]:
					self._attrs[attr] = nl.nla_data(attrs[attr])
			except Exception as e:
				print e.message
				self._attrs[attr] = nl.nla_data(attrs[attr])

	@property
	def attrs(self):
		return self._attrs

	def get_nlattr(self, attr_id):
		return self._attrs[attr_id]

class nl80211_managed_object(nl80211_object, ValidHandler):
	def __init__(self, access, attrs, policy=None):
		nl80211_object.__init__(self, attrs, policy)
		self._access = access

	@property
	def objcmd(self):
		try:
			return self._cmd
		except Exception:
			raise Exception('class need to define _cmd attribute')

	@abstractmethod
	def put_obj_id(m):
		pass

	def refresh(self):
		m = self._access.alloc_genlmsg(self.objcmd, nlc.NLM_F_REQUEST | nlc.NLM_F_ACK)
		self.put_obj_id(m)
		self._access.send(m, self)

	def handle(self, msg, arg):
		try:
			e, attrs = genl.py_genlmsg_parse(nl.nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			self.store_attrs(attrs)
			return nl.NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)

