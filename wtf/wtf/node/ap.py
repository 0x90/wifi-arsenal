# Copyright cozybit, Inc 2010-2011
# All rights reserved

import textwrap

import wtf.node as node


class APBase(node.NodeBase):

    """
    Access Point

    This represents the platform-independent AP that should be used by tests.

    Real APs should extend this class and implement the actual AP functions.
    """

    def __init__(self, comm):
        """
        Create an AP with the supplied default configuration.
        """
        node.NodeBase.__init__(self, comm=comm)

# Security options
SECURITY_WEP = 1
SECURITY_WPA = 2
SECURITY_WPA2 = 3

# Client authentication schemes.  None is used to represent open.
AUTH_PSK = 1
AUTH_EAP = 2

# Encryption ciphers
ENCRYPT_TKIP = 1
ENCRYPT_CCMP = 2


class APConfig():

    """
    Access Point configuration object

    Access Points have all sorts of configuration variables.  Perhaps the most
    familiar ones are the SSID and the channel.
    """

    def __init__(self, ssid, channel=11, band='g', security=None, auth=None,
                 password=None, encrypt=None):
        self.ssid = ssid
        self.band = band
        self.channel = channel
        self.security = security
        self.auth = auth
        self.password = password
        self.encrypt = encrypt
        if security == SECURITY_WEP and not password:
            raise InsufficientConfigurationError("WEP requires a password")
        if (security == SECURITY_WPA or security == SECURITY_WPA2) and \
                (not password or not auth):
            raise InsufficientConfigurationError(
                "WPA(2) requires a password and auth scheme")


class Hostapd(node.LinuxNode, APBase):

    """
    Hostapd-based AP
    """

    def __init__(self, comm, iface, ops=None):
        node.LinuxNode.__init__(self, comm, iface, ops=ops)
        self.config = None

    def start(self):
        # iface must be down before we can set type
        node.LinuxNode.stop(self)
        self._cmd_or_die("iw " + self.iface[0].name + " set type __ap")
        node.LinuxNode.start(self)
        if not self.config:
            raise node.InsufficientConfigurationError()
        self._configure()
        self._cmd_or_die("hostapd -B /tmp/hostapd.conf")

    def stop(self):
        node.LinuxNode.stop(self)
        self.comm.send_cmd("killall hostapd")
        self.comm.send_cmd("iw dev mon." + self.iface[0].name + " del")
        self.comm.send_cmd("rm -f /var/run/hostapd/" + self.iface[0].name)

# some of this stuff, like channel, ht_capab, and hw_mode are target-specific,
# use 'iw <dev> list' to parse capabilities?
    base_config = textwrap.dedent("""
        driver=nl80211
        logger_syslog=-1
        logger_syslog_level=2
        logger_stdout=-1
        logger_stdout_level=0
        dump_file=/tmp/hostapd.dump
        ctrl_interface=/var/run/hostapd
        ctrl_interface_group=0
        beacon_int=100
        dtim_period=2
        max_num_sta=255
        rts_threshold=2347
        fragm_threshold=2346
        macaddr_acl=0
        auth_algs=3
        ignore_broadcast_ssid=0
        own_ip_addr=127.0.0.1
        """)

    def _configure(self):
        config = self.base_config
        config += "ssid=" + self.config.ssid + "\n"
        config += "hw_mode=%c\n" % self.config.band
        config += "channel=%d\n" % self.config.channel
        config += "interface=" + self.iface[0].name + "\n"
        if self.config.security != None:
            if self.config.security == SECURITY_WPA:
                config += "wpa=1\n"
            elif self.config.security == SECURITY_WPA2:
                config += "wpa=2\n"
        if self.config.auth != None:
            if self.config.auth == AUTH_PSK:
                config += "wpa_key_mgmt=WPA-PSK\n"
                config += 'wpa_passphrase="' + self.config.password + '"\n'
        if self.config.encrypt != None:
            if self.config.encrypt == ENCRYPT_TKIP:
                config += "wpa_pairwise=TKIP\n"
            elif self.config.encrypt == ENCRYPT_CCMP:
                config += "wpa_pairwise=CCMP\n"
        # can we enable 11n?
        if self.config.security == None or \
            (self.config.security == SECURITY_WPA2 and
             self.config.encrypt == ENCRYPT_CCMP):
                config += "ieee80211n=1\n"
                # these sensible defaults should work for most cards, instead of checking for valid
                # channel, band, and HT40+/- combination, we let hostapd take
                # care of it.
                config += "ht_capab=[HT40-]\n"
                # is this really needed? linux-wireless wiki says so in an underhanded manner (http://wireless.kernel.org/en/users/Documentation/hostapd)
                # check the 11n standard. Enabled for now.
                config += textwrap.dedent("""
                    wmm_enabled=1
                    wmm_ac_bk_cwmin=4
                    wmm_ac_bk_cwmax=10
                    wmm_ac_bk_aifs=7
                    wmm_ac_bk_txop_limit=0
                    wmm_ac_bk_acm=0
                    wmm_ac_be_aifs=3
                    wmm_ac_be_cwmin=4
                    wmm_ac_be_cwmax=10
                    wmm_ac_be_txop_limit=0
                    wmm_ac_be_acm=0
                    wmm_ac_vi_aifs=2
                    wmm_ac_vi_cwmin=3
                    wmm_ac_vi_cwmax=4
                    wmm_ac_vi_txop_limit=94
                    wmm_ac_vi_acm=0
                    wmm_ac_vo_aifs=2
                    wmm_ac_vo_cwmin=2
                    wmm_ac_vo_cwmax=3
                    wmm_ac_vo_txop_limit=47
                    wmm_ac_vo_acm=0""")

        self._cmd_or_die("echo -e \"" + config + "\"> /tmp/hostapd.conf",
                         verbosity=0)
