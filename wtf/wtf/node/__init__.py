# Copyright cozybit, Inc 2010-2011
# All rights reserved

"""WTF network node definitions."""

import os
import time
from collections import namedtuple

from wtf.util import CapData
from wtf.util import PerfConf
from wtf.util import parse_perf_report


NOT_MODPROBE_ABLE = ["mwl8787_sdio", "wcn36xx_msm"]


class UninitializedError(Exception):

    """Raised when routines are called prior to initialization."""


class InsufficientConfigurationError(Exception):

    """Raised on insufficient configuration information."""


class UnsupportedConfigurationError(Exception):

    """Raised when an unsupported configuration has been attempted."""


class ActionFailureError(Exception):

    """Raised when an action on a node fails."""


class NodeBase(object):

    """A network node that will participate in tests.

    A network node could be an AP, a mesh node, a client STA, or some new thing
    that you are inventing.  Minimally, it can be initialized and shutdown
    repeatedly.  So init and shutdown are really not the same thing as __init__
    and __del__.  Once a node has been successfully initialized, it can be
    started and stopped, repeatedly.

    """

    def __init__(self, comm):
        self.initialized = False
        self.comm = comm

    def init(self):
        """Initialize the node.

        override this method to customize how your node is initialized.  For
        some nodes, perhaps nothing is needed.  Others may have to be powered
        on and configured.

        """
        self.initialized = True

    def shutdown(self):
        """Shutdown the node.

        Override this method to customize how your node shuts down.

        """
        self.initialized = False

    def start(self):
        """Start the node in its default configuration.

        Raises an `UninitializedError` if `init` was not called.

        Raises an `InsufficientConfigurationError` exception if sufficient
        default values are not available.

        """
        if not self.initialized:
            raise UninitializedError()
        raise InsufficientConfigurationError()

    def stop(self):
        """Stop the node."""

    def set_ip(self, iface, ipaddr):
        """Set the ip address of a node."""
        raise NotImplementedError("set_ip is not implemented for this node")

    def ping(self, host, timeout=2, count=1):
        """Ping a remote host from this node.

        :param timeout: seconds to wait before quitting
        :param count: number of ping requests to send
        :param interval: time in between pings
        :returns: 0 on success, anything else on failure
        :returns: a named tuple return_code and stdout

        """
        raise NotImplementedError("ping is not implemented for this node")

    def _cmd_or_die(self, cmd, verbosity=None):
        (r, o) = self.comm.send_cmd(cmd, verbosity)
        if r != 0:
            raise ActionFailureError("Failed to \"" + cmd + "\"")
        return o


class Iface(object):

    """Wifi interface.

    Includes the associated driver, ip and maybe a monitor interface.

    """

    _driver_specific = {}

    @classmethod
    def register_driver_specific(cls, driver, klass):
        """Register a driver specific class. See `create_iface`."""
        cls._driver_specific[driver] = klass

    @classmethod
    def create_iface(cls, name=None, driver=None, ip=None,
                     mcast_route=None, conf=None, ops=None):
        """Return an Iface object specific to a `driver`."""

        klass = cls
        if driver in cls._driver_specific:
            klass = cls._driver_specific[driver]

        return klass(name=name, driver=driver, ip=ip, mcast_route=mcast_route,
                     conf=conf, ops=ops)

    def __init__(self, name=None, driver=None, ip=None, mcast_route=None,
                 conf=None, ops=None):
        # TODO: Just make name not optional...
        if not name:
            raise InsufficientConfigurationError("need iface name")
        self.ip = ip
        self.mcast_route = mcast_route
        self.name = name
        self.driver = driver
        self.conf = conf
        self.enable = True
        self.perf = None
        self.node = None
        self.phy = None
        self.mac = None
        self.cap = None
        self.ref_clip = None
        self.video_file = None
        self._ops = PlatformOps(None)
        if ops is not None:
            self._ops = ops

    def start_perf(self, conf):
        """Start an iperf sessions."""

        if conf.dst_ip is None:
            conf.dst_ip = self.ip

        self.perf = conf
        self.perf.log = self._ops.get_perf_log_loc(self.name)

        if conf.server:
            cmd = "iperf -s -p" + str(conf.listen_port)
            if not conf.tcp:
                cmd += " -u"
            if conf.dst_ip:
                cmd += " -B" + conf.dst_ip
            # -x  [CDMSV]   exclude C(connection) D(data) M(multicast)
            # S(settings) V(server) reports
            cmd += " -y c -x CS > " + self.perf.log
            cmd += " &"
        else:
            # in o11s the mpath expiration is pretty aggressive (or it hasn't
            # been set up yet), so prime it with a ping first. Takes care of
            # initial "losses" as the path is refreshed.
            self.node.ping(conf.dst_ip, verbosity=3, timeout=3, count=3)
            self.dump_mpaths()
            cmd = "iperf -c " + conf.dst_ip + \
                  " -i1 -t" + str(conf.timeout) + \
                  " -p" + str(conf.listen_port)
            if not conf.tcp:
                cmd += " -u -b" + str(conf.bw) + "M"
            if conf.dual:
                cmd += " -d -L" + str(conf.dual_port)
            if conf.fork:
                cmd += " &"

        _, o = self.node.comm.send_cmd(cmd)
        if not conf.server and not conf.fork:
            # we blocked on completion and report is ready now
            self.perf.report = o[1]
        else:
            _, o = self.node.comm.send_cmd("echo $!")
            self.perf.pid = int(o[-1])

    def perf_serve(self, dst_ip=None, p=7777, tcp=False):
        """Start an iperf server."""
        self.start_perf(PerfConf(server=True, dst_ip=dst_ip, p=p, tcp=tcp))

    def perf_client(self, dst_ip=None, timeout=5, dual=False, b=10, p=7777,
                    L=6666, fork=False, tcp=False):
        """Start an iperf client."""
        if dst_ip is None:
            raise InsufficientConfigurationError("need dst_ip for perf")
        self.start_perf(PerfConf(dst_ip=dst_ip, timeout=timeout,
                                 dual=dual, b=b, p=p, L=L, fork=fork,
                                 tcp=tcp))

    def killperf(self):
        """Kill the remote iperf server."""
        if self.perf.pid is None:
            return
        self.node.comm.send_cmd("while kill %d 2>/dev/null; do sleep 1; done" %
                                (self.perf.pid,))
        self.node.comm.send_cmd("while kill %d 2>/dev/null; do sleep 1; done" %
                                (self.perf.pid,))
        self.perf.pid = None

    def get_perf_report(self):
        """Parse the remote iperf remote.

        :returns: An `IperfReport` object.

        """
        self.killperf()
        _, o = self.node.comm.send_cmd("cat " + self.perf.log)
        print "parsing perf report"
        return parse_perf_report(self.perf, o)

    def video_serve(self, video=None, ip=None, port=5004):
        """Serve `video` to `dst_ip` using VLC.

        Blocks until stream completion

        """
        if ip is None or video is None:
            raise InsufficientConfigurationError(
                "need a reference clip and destination ip!")
        print "%s: starting video server" % (self.ip,)
        self.ref_clip = "/tmp/" + os.path.basename(video)
        self.comm.put_file(video, self.ref_clip)
        # prime mpath so we don't lose inital frames in unicast!
        self.node.ping(ip, verbosity=0)
        self.node.comm.send_cmd(
            "su nobody -c 'vlc -I dummy %s"
            " :sout=\"#rtp{dst=%s,port=%d,mux=ts,ttl=1}\" :sout-all"
            " :sout-keep vlc://quit' &> /tmp/video.log"
            % (self.ref_clip, ip, port))

    def video_client(self, out_file=None, ip=None, port=5004):
        """Start VLC on the node."""
        print "%s: starting video client" % (self.ip,)
        if ip is None:
            raise InsufficientConfigurationError(
                "need a reference clip and destination ip!")
        if out_file is None:
            out_file = "/tmp/" + self.name + "_video.ts"
        self.video_file = out_file
        self.node.comm.send_cmd(
            "su nobody -c 'vlc -I dummy rtp://%s:%d "
            "--sout file/ts:%s' &> /tmp/video.log &"
            % (ip, port, self.video_file))

    def killvideo(self):
        """Kill node's video client (vlc)."""
        self.node.comm.send_cmd("killall -w vlc")
        self.node.comm.send_cmd("cat /tmp/video.log")

    def get_video(self, path="/tmp/out.ts"):
        """Fetch captured video file from node."""
        if self.video_file is None:
            pass
        self.killvideo()
        self.node.comm.get_file(self.video_file, path)

    def start_capture(self, cap_file=None, snaplen=300, promisc=False,
                      eth=False):
        """Start a packet capture on the node.

        Note the low `snaplen`, this is to prioritize no dropped packets over
        getting the whole payload.

        """
        if not cap_file:
            cap_file = "/tmp/" + self.name + "_out.cap"
        if not self.cap:
            self.cap = CapData(cap_file=cap_file)
        else:
            self.cap.node_cap = cap_file
        self.cap.snaplen = snaplen

        if not self.cap.monif and eth:
            # capturing on an ethernet iface, nothing special
            self.cap.monif = self.name
        # if no monif configured, attach to this interface in non-promiscuous
        elif not self.cap.monif:
            self.cap.monif = self.name + ".mon"
            self.node._cmd_or_die("iw dev %s interface add %s type monitor" %
                                  (self.name, self.cap.monif))
            self.node._cmd_or_die("ip link set %s up" % (self.cap.monif))
            self.cap.promisc = promisc

        cmd = "tcpdump -i %s -U " % (self.cap.monif)
        if not self.cap.promisc:
            cmd += "-p "
        if self.cap.snaplen:
            cmd += "-s %d " % (self.cap.snaplen)
        cmd += "-w %s &" % (self.cap.node_cap)
        self.node.comm.send_cmd(cmd)
        _, o = self.node.comm.send_cmd("echo $!")
        self.cap.pid = int(o[-1])

    def get_capture(self, path=None):
        """Return path to capture file now available on local system."""
        if not path:
            import tempfile
            path = tempfile.mktemp()
        self.node.comm.get_file(self.cap.node_cap, path)
        # save a pointer
        self.cap.local_cap = path
        return path

    def stop_capture(self, path=None):
        """Stop capture and return a copy for analysis."""
        if not self.cap:
            return
        self.node.comm.send_cmd(
            "while kill %d 2>/dev/null; do sleep 1; done" % (self.cap.pid,))
        self.cap.pid = None
        return self.get_capture(path)

    def add_mesh_peer(self, peer):
        """Add a mesh peer to the node."""
        # TODO: Mesh-specific goes in MeshIface (or MeshSTA)?
        self.node.comm.send_cmd("iw %s station set %s plink_action open" %
                                (self.name, peer.mac))

    def dump_mpaths(self):
        """Dump mpaths."""
        self.node.comm.send_cmd("iw %s mpath dump" % (self.name))

    def dump_mesh_stats(self):
        """Dump mesh status of the node."""
        self.node.comm.send_cmd(
            "grep \"\" /sys/kernel/debug/ieee80211/%s/netdev\\:%s/mesh_stats/*"
            % (self.phy, self.name))

    def dump_phy_stats(self):
        """Dump phy stats of the node."""
        self.node.comm.send_cmd(
            "grep \"\" /sys/kernel/debug/ieee80211/%s/statistics/*"
            % (self.phy))

    def link_up(self):
        """Bring the nodes link up."""
        self.node.comm.send_cmd("ip link set %s up" % (self.name))

    def set_radio(self, state):
        """Turn on or off the radio"""
        # FIXME
        if self.driver == "mwl8787_sdio":
            self.node.comm.send_cmd(
                "echo %d > /sys/kernel/debug/ieee80211/%s/mwl8787/radio_set" % (state, self.phy))
        else:
            raise NotImplementedError(
                "Not yet implemented for %s" % (self.driver))

    def load_module(self):
        """Load the driver's module, if this is a support configuration.

        See also `Mwl8787Iface` and `Wc36xxIface`."""

        if self.driver in NOT_MODPROBE_ABLE:
            raise UnsupportedConfigurationError(
                "Iface driver not loadable with modprobe")

        self.node._cmd_or_die("modprobe " + self.driver)


# allows commands to return either return code or stdout so the caller
# verbosely names which of the two if any they want to use
CommandResult = namedtuple("CommandResult", ['return_code', 'stdout'])


class Mwl8787Iface(Iface):

    """Iface with ops specific to the Marvel 8787 chip.

    See also `Iface`.

    """

    def load_module(self):
        """See `Iface.load_module`."""

        if self.driver != "mwl8787_sdio":
            raise UnsupportedConfigurationError(
                "Only the mwl8787_sdio driver is supported.")

        self.node.comm.send_cmd("rmmod " + self.driver)
        cmd = "/system/bin/mwl8787_config.sh"
        self.node._cmd_or_die(cmd, verbosity=3)
        # give ifaces time to come up
        time.sleep(1)


Iface.register_driver_specific("mwl8787_sdio", Mwl8787Iface)


class Wcn36xxIface(Iface):

    """Iface with ops specific to the WCN36XX chips on MSM.

    See also `Iface`.

    """

    def load_module(self):
        """See `Iface.load_module`."""

        if self.driver != "wcn36xx_msm":
            raise UnsupportedConfigurationError(
                "Only the wcn36xx_msm driver is supported.")

        self._ops.reboot()


Iface.register_driver_specific("wcn36xx_msm", Wcn36xxIface)


class PlatformOps(object):

    """Abstraction for various paltforms specific operations."""

    def __init__(self, comm):
        self._comm = comm

    def beforeInit(self, path):
        """Perform initialization required prior to init().

        Usually things like clearing system state and setting up the host
        filesystem.

        """

        if path is not None:
            self._comm.send_cmd("export PATH=" + path + ":$PATH:", verbosity=0)

        # who knows what was running on this machine before.  Be sure to kill
        # anything that might get in our way.
        self._comm.send_cmd("killall hostapd; killall wpa_supplicant",
                            verbosity=0)

        # make sure debugfs is mounted
        _, mounted = self._comm.send_cmd("mount | grep debugfs", verbosity=0)
        # "debugfs /sys/kernel/debug debugfs rw,relatime 0 0" or empty
        if len(mounted) > 0:
            if mounted[0].split(' ')[1] != '/sys/kernel/debug':
                self._comm.send_cmd("umount debugfs", verbosity=0)
                self._comm.send_cmd(
                    "mount -t debugfs debugfs /sys/kernel/debug", verbosity=0)
        else:
            self._comm.send_cmd(
                "mount -t debugfs debugfs /sys/kernel/debug", verbosity=0)

    def _get_tmp(self):
        return "/tmp"

    def get_perf_log_loc(self, name):
        """Return an iperf log appropriate for the platform."""
        return os.path.join(self._get_tmp(), "iperf_" + name + ".log")

    def reboot(self):
        self._comm.reboot()


class AndroidPlatformOps(PlatformOps):

    """Provides platform specific code for Android nodes."""

    def _get_tmp(self):
        return "/data/misc/"


class LinuxNode(NodeBase):

    """
    A linux network node.

    Expects: iw, mac80211 debugfs

    """

    def __init__(self, comm, ifaces=(), path=None, ops=None):
        self._ops = PlatformOps(None)
        if ops is not None:
            self._ops = ops
        self.iface = list(ifaces)
        for iface in self.iface:
            iface.node = self
        self.brif = None
        NodeBase.__init__(self, comm)
        self._ops.beforeInit(path)

    def init(self):
        """Initialize the node, including network interfaces."""

        for iface in self.iface:
            if not iface.enable:
                continue

            iface.load_module()

            # TODO: check for error and throw something!
            _, iface.phy = self.comm.send_cmd(
                "echo `find /sys/kernel/debug/ieee80211 -name netdev:" +
                iface.name + " | cut -d/ -f6`", verbosity=0)
            _, iface.mac = self.comm.send_cmd(
                "echo `ip link show " + iface.name +
                " | awk '/ether/ {print $2}'`", verbosity=0)

            # TODO: Python people help!!
            iface.phy = iface.phy[0]
            iface.mac = iface.mac[0]

        self.initialized = True

    def shutdown(self):
        """Shutdown the node: remove all modules, stop services."""
        self.stop()
        for iface in self.iface:
            if iface.driver:
                self.comm.send_cmd("modprobe -r " + iface.driver)
                if iface.cap:
                    iface.cap.monif = None
        # stop meshkitd in case it's installed
        self.comm.send_cmd("/etc/init.d/meshkit stop")
        self.initialized = False

    def start(self):
        """Start the node: brind up interfaces, set address."""
        if not self.initialized:
            raise UninitializedError()
        for iface in self.iface:
            if not iface.enable:
                continue
            # TODO: config.iface.set_ip()?
            if iface.ip:
                self.set_ip(iface.name, iface.ip)
            if iface.mcast_route:
                self.set_mcast(iface, iface.mcast_route)

    def stop(self):
        """Stop the node: interface downed and interface deleted."""
        for iface in self.iface:
            self.comm.send_cmd("ifconfig " + iface.name + " down")
        self.del_brif()

    def set_ip(self, name, ipaddr):
        """Set the node's IP address."""
        self.comm.send_cmd("ifconfig " + name + " " + ipaddr + " up")

    def set_mcast(self, iface, mcast_route):
        """Set node's multicast route."""
        self.comm.send_cmd(
            "route add -net %s netmask 255.255.255.255 %s"
            % (mcast_route, iface.name))

    def ping(self, host, timeout=3, count=1, verbosity=2, interval=1):
        """Start ping from this node to `host`. Return ping output."""
        cmd = "ping -c " + str(count)
        cmd += " -i " + str(interval)
        cmd += " -w " + str(timeout) + " " + host
        result = self.comm.send_cmd(cmd, verbosity=verbosity)
        return CommandResult(return_code=result[0], stdout=result[1])

    def if_down(self, iface):
        """Bring down node's network interface."""
        self.comm.send_cmd("ifconfig " + iface + " down")

    def del_brif(self):
        """Delete node's bridge interface."""
        if not self.brif:
            return
        self.if_down(self.brif)
        self.comm.send_cmd("brctl delbr " + self.brif)

    def bridge(self, ifaces, ip):
        """Bridge interfaces.

        :param ifaces: interfaces to bridge, first mac of `ifaces` it assigned
                       bridge interface.
        :param ip: ip to assign to bridge

        """
        bridge = "br0"
        self.del_brif()
        self.brif = bridge
        self._cmd_or_die("brctl addbr " + bridge)
        for iface in ifaces:
            self.comm.send_cmd("ip addr flush " + iface.name)
            self._cmd_or_die("brctl addif %s %s " % (bridge, iface.name))
        self._cmd_or_die("ip link set br0 address %s" % (ifaces[0].mac))
        self.set_ip("br0", ip)

    def bond_reload(self):
        """Reload the "bonding" module."""
        self.comm.send_cmd("modprobe -r bonding")
        self.comm.send_cmd("modprobe bonding")

    def bond(self, ifaces, ip):
        """Bond interfaces in `ifaces` and assign `ip`."""
        self.bond_reload()
        self.set_ip("bond0", ip)
        for iface in ifaces:
            self._cmd_or_die("ip addr flush " + iface.name)
            self._cmd_or_die("ifenslave bond0 " + iface.name)
