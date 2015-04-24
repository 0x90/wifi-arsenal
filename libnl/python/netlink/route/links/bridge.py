#
# Copyright (c) 2013 Nicolas PLANEL <nicolas.planel@enovance.com>
#

"""BRIDGE network link

"""

from __future__ import absolute_import

from ... import core as netlink
from ..  import capi as capi

class BRIDGELink(object):
    def __init__(self, link):
        self._link = link
        self._has_ext_info = capi.rtnl_link_bridge_has_ext_info(self._link)
        self._port_state_values = ['disabled','listening','learning','forwarding','blocking']

    def bridge_assert_ext_info(self):
        if self._has_ext_info == False:
            print """
            Please update your kernel to be able to call this method.
            Your current kernel bridge version is too old to support this extention.
            """
            raise RuntimeWarning()

    def port_state2str(self, state):
        return self._port_state_values[state]

    def str2port_state(self, str):
        for value, port in enumerate(self._port_state_values):
            if str.lower() == port:
                return value
        raise ValueError()

    @property
    @netlink.nlattr(type=int)
    def port_state(self):
        """bridge state :
        %s
        """ % (self.port_state)
        return capi.rtnl_link_bridge_get_state(self._link)

    @port_state.setter
    def port_state(self, state):
        capi.rtnl_link_bridge_set_state(self._link, int(state))

    @property
    @netlink.nlattr(type=int)
    def priority(self):
        """bridge prio
        """
        bridge_assert_ext_info()
        return capi.rtnl_link_bridge_get_prio(self._link)

    @priority.setter
    def priority(self, prio):
        bridge_assert_ext_info()
        if prio < 0 or prio >= 2**16:
            raise ValueError()
        capi.rtnl_link_bridge_set_prio(self._link, int(prio))

    @property
    @netlink.nlattr(type=int)
    def cost(self):
        """bridge prio
        """
        bridge_assert_ext_info()
        return capi.rtnl_link_bridge_get_cost(self._link)

    @cost.setter
    def cost(self, cost):
        bridge_assert_ext_info()
        if cost < 0 or cost >= 2**32:
            raise ValueError()
        capi.rtnl_link_bridge_set_cost(self._link, int(cost))

    @property
    @netlink.nlattr(type=str)
    def flags(self):
        """ BRIDGE flags
        Setting this property will *Not* reset flags to value you supply in
        Examples:
        link.flags = '+xxx' # add xxx flag
        link.flags = 'xxx'  # exactly the same
        link.flags = '-xxx' # remove xxx flag
        link.flags = [ '+xxx', '-yyy' ] # list operation
        """
        self.bridge_assert_ext_info()
        flags = capi.rtnl_link_bridge_get_flags(self._link)
        return capi.rtnl_link_bridge_flags2str(flags, 256)[0].split(',')

    def _set_flag(self, flag):
        if flag.startswith('-'):
            i = capi.rtnl_link_bridge_str2flags(flag[1:])
            capi.rtnl_link_bridge_unset_flags(self._link, i)
        elif flag.startswith('+'):
            i = capi.rtnl_link_bridge_str2flags(flag[1:])
            capi.rtnl_link_bridge_set_flags(self._link, i)
        else:
            i = capi.rtnl_link_bridge_str2flags(flag)
            capi.rtnl_link_bridge_set_flags(self._link, i)

    @flags.setter
    def flags(self, value):
        self.bridge_assert_ext_info()
        if type(value) is list:
            for flag in value:
                self._set_flag(flag)
        else:
            self._set_flag(value)

    def brief(self):
        return 'bridge-has-ext-info {0}'.format(self._has_ext_info)

def init(link):
    link.bridge = BRIDGELink(link._rtnl_link)
    return link.bridge
