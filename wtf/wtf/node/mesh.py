# Copyright cozybit, Inc 2010-2012
# All rights reserved

import textwrap

import wtf.node as node
import sys
err = sys.stderr


class MeshBase(node.NodeBase):

    """
    Mesh STA

    This represents a platform-independent mesh STA that should be used by tests.

    Real Mesh STAs should extend this class and implement the actual AP functions.
    """

    def __init__(self, comm):
        """
        Create mesh STA with the supplied default configuration.
        """
        node.NodeBase.__init__(self, comm=comm)


class MeshConf():

    """
    Mesh STA configuration object

    Use this to set options for the MBSS; SSID, channel, etc.
    XXX: add support for authsae
    """

    def __init__(self, ssid, channel=1, htmode="", security=0, iface=None,
                 mesh_params=None, mcast_rate=None, shared=False):
        if not iface:
            raise node.UninitializedError("need iface for mesh config")
        self.iface = iface
        self.ssid = ssid
        self.channel = channel
        self.htmode = htmode
        self.security = security
        self.mesh_params = mesh_params
        self.mcast_rate = mcast_rate
        self.shared = shared


class MeshSTA(node.LinuxNode, MeshBase):

    """
    mesh STA node
    """

    def __init__(self, comm, ifaces, ops=None):
        node.LinuxNode.__init__(self, comm, ifaces, ops=ops)
        self.mccapipe = None

    def start(self):
        # XXX: self.stop() should work since we extend LinuxNode??
        node.LinuxNode.stop(self)

        for iface in self.iface:
            if iface.enable != True:
                continue
            # self.set_iftype("mesh")
            self._cmd_or_die("iw dev " + iface.name + " set type mp")
            # node.set_channel(self.config.channel)
            self._cmd_or_die("iw dev " + iface.name + " set channel " + str(iface.conf.channel) +
                             " " + iface.conf.htmode)
            # must be up for authsae or iw
            self._cmd_or_die("ifconfig " + iface.name + " up")
            if iface.conf.security:
                self.authsae_join(iface.conf)
            else:
                self.mesh_join(iface.conf)
        node.LinuxNode.start(self)

    def stop(self):
        for iface in self.iface:
            if iface.enable != True:
                continue
            config = iface.conf
            if config.security:
                self.comm.send_cmd(
                    "start-stop-daemon --quiet --stop --exec meshd-nl80211")
            else:
                self.comm.send_cmd(
                    "iw dev " + config.iface.name + " mesh leave")
        self.mccatool_stop()
        node.LinuxNode.stop(self)

    def authsae_join(self, config):
        # This is the configuration template for the authsae config
        confpath = "/tmp/authsae-%s.conf" % (config.iface.name)
        logpath = "/tmp/authsae-%s.log" % (config.iface.name)
        security_config_base = textwrap.dedent('''
        /* this is a comment */
        authsae:
        {
            sae:
            {
                debug = 480;
                password = \\"thisisreallysecret\\";
                group = [19, 26, 21, 25, 20];
                blacklist = 5;
                thresh = 5;
                lifetime = 3600;
            };
            meshd:
            {
                meshid = \\"%s\\";
                interface = \\"%s\\";
                band = \\"11g\\";
                channel = %s;
                htmode = \\"none\\";
                mcast-rate = 12;
            };
        };
        ''' % (str(config.ssid), str(config.iface.name), str(config.channel)))

        self._cmd_or_die("echo -e \"" + security_config_base + "\"> %s" %
                         (confpath), verbosity=0)
        self._cmd_or_die("meshd-nl80211 -c %s %s &" % (confpath, logpath))

    def mesh_join(self, config):
        cmd = "iw %s mesh join %s" % (config.iface.name, config.ssid)
        if config.mcast_rate:
            cmd += " mcast-rate %s" % (config.mcast_rate)

#        cmd += " share"
#        if config.shared:
#            cmd += " on"
#        else:
#            cmd += " off"
        if config.mesh_params:
            cmd += " " + config.mesh_params
        self._cmd_or_die(cmd)

# restart mesh node
    def reconf(self):
        # LinuxNode.shutdown()????
        self.shutdown()
        self.init()
        self.start()

# empty owner means just configure own owner reservation, else install
# specified interference reservation.
    def set_mcca_res(self, owner=None):
        if not self.mccapipe:
            raise node.InsufficientConfigurationError()

        if owner != None:
            self._cmd_or_die("echo i %d %d %d > %s" % (owner.res.offset,
                                                       owner.res.duration,
                                                       owner.res.period,
                                                       self.mccapipe))
        else:
            self._cmd_or_die("echo a %d %d > %s" % (self.res.duration,
                                                    self.res.period,
                                                    self.mccapipe))

    def mccatool_start(self, config=None):
        if not config:
            config = self.iface[0].conf
        if not self.mccapipe:
            import tempfile
            self.mccapipe = tempfile.mktemp()
            self._cmd_or_die("mkfifo %s" % self.mccapipe)
# keep the pipe open :|
            self._cmd_or_die("nohup sleep 10000 > %s &" % self.mccapipe)

        self._cmd_or_die(
            "nohup mccatool %s > /tmp/mccatool.out 2> /dev/null < %s &" %
            (config.iface.name, self.mccapipe))

    def mccatool_stop(self, config=None):
        if not config:
            config = self.iface[0].conf
        if self.mccapipe:
            self.comm.send_cmd("killall mccatool")
            self.comm.send_cmd("rm %s" % self.mccapipe)
            self.mccapipe = None


class MeshKitSTA(MeshSTA):

    """MeshSTA that uses meshkit instead of iw."""

    def start(self):
        node.LinuxNode.stop(self)

        for iface in self.iface:
            if iface.enable is not True:
                continue
            if iface.conf.security:
                raise NotImplementedError(
                    "This version of meshkit does not yet support secure mesh")
            self.comm.send_cmd("mesh " + iface.name + " up " + iface.conf.ssid +
                               " " + str(iface.conf.channel) + " " + iface.conf.htmode)
        node.LinuxNode.start(self)

    def stop(self):
        for iface in self.iface:
            if iface.enable != True:
                continue
            config = iface.conf
            if config.security:
                raise NotImplementedError(
                    "This version of meshkit does not yet support secure mesh")
            else:
                self.comm.send_cmd("mesh " + config.iface.name + " down")
        self.mccatool_stop()
        node.LinuxNode.stop(self)
