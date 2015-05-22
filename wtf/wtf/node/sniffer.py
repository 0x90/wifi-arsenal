# Copyright cozybit, Inc 2010-2012
# All rights reserved

from wtf.util import *
import wtf.node as node
import sys
err = sys.stderr


class SnifferBase(node.NodeBase):

    """
    Sniffer STA

    This represents a platform-independent monitor STA that should be used by tests.

    Real Sniffer STAs should extend this class and implement the actual AP functions.
    """

    def __init__(self, comm):
        """
        Create sniffer STA with the supplied default configuration.
        """
        node.NodeBase.__init__(self, comm=comm)


class SnifferConf():

    def __init__(self, channel=1, htmode="", iface=None):
        self.channel = channel
        self.htmode = htmode
        self.iface = iface


class SnifferSTA(node.LinuxNode, SnifferBase):

    def __init__(self, comm, ifaces):
        node.LinuxNode.__init__(self, comm, ifaces)

    def start(self):
        for iface in self.iface:
            self._cmd_or_die("iw " + iface.name + " set type monitor")
            self._cmd_or_die("iw " + iface.name + " set monitor control")
            self._cmd_or_die("ifconfig " + iface.name + " up")
            self._cmd_or_die("iw " + iface.name + " set channel " + str(iface.conf.channel) +
                             " " + iface.conf.htmode)
            iface.cap = CapData(monif=iface.name, promisc=True)

    def stop(self):
        node.LinuxNode.stop(self)
