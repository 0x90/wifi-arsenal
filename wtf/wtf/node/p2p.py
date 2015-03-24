# Copyright cozybit, Inc 2010-2011
# All rights reserved

import wtf.node as node
import time
import random

WPS_METHOD_NONE = 0x0000
WPS_METHOD_PBC = 0x0080
WPS_METHOD_DISPLAY = 0x0008
WPS_METHOD_KEYPAD = 0x0100
WPS_METHOD_LABEL = 0x0004


class P2PBase(node.NodeBase):

    """
    Peer-to-Peer node (i.e., wifi direct)

    This represents the platform-independent P2P node that should be used by
    tests.  If the GO intent is not specified, the default value of 6 is used.
    If a test wishes to change this value, it must do so before invoking start.
    """

    def __init__(self, comm, intent=6):
        """
        Create a P2P node with the supplied default comm channel.
        """
        node.NodeBase.__init__(self, comm=comm)
        self.intent = intent

    def find_start(self):
        pass

    def find_stop(self):
        pass

    def peers(self):
        pass

    def connect_start(self, peer, method=WPS_METHOD_PBC):
        """
        Initiate a connection with the specified peer and method

        return 0 for success and non-zero for failure.  This function should
        not block waiting for the WPS dialog to proceed.  It should return and
        expect a call to connect_finish after the peer's button has been
        pressed or pin entered depending on the method.  That function can
        check the status of the WPS dialog and finalize the connection as
        necessary.
        """
        pass

    def connect_allow(self, peer, method=WPS_METHOD_PBC):
        """
        Allow negotiation with the specified peer

        return 0 on success and non-zero for failure.  This function can be
        called instead of connect_start if the p2p node is to expect connection
        attempts from the specified peer.
        """
        pass

    def pbc_push(self):
        """
        Push the PBC button.

        return 0 for success and non-zero for failure.  Note that this is most
        sensibly called after somebody else somewhere has called connect_start
        with the pbc method.
        """
        pass

    def connect_finish(self, peer):
        """
        Finish the connection

        return 0 if the WPS dialog terminated successfully and a link is
        available.
        """
        pass


class Peer:

    """
    Peer

    This is the wtf representation of a peer used to communicate detected peers
    between P2P classes and tests.
    """

    def __init__(self, mac, name):
        self.mac = mac
        self.intended_mac = mac
        self.name = name


class Wpap2p(P2PBase, node.sta.LinuxSTA):

    """
    wpa_supplicant-based AP
    """

    def __init__(self, comm, iface, driver=None, path="/root"):
        node.LinuxNode.__init__(self, comm, iface, driver, path)
        P2PBase.__init__(self, comm)
        self.name = comm.name.replace(" ", "-")
        (r, self.mac) = comm.send_cmd(
            "cat /sys/class/net/" + iface + "/address")
        self.mac = self.mac[0]

    base_config = """
ctrl_interface=/var/run/wpa_supplicant
ap_scan=1
device_type=1-0050F204-1
# optional, can be useful for monitoring, forces
# wpa_supplicant to use only channel 1 rather than
# 1, 6 and 11:
#p2p_listen_reg_class=81
#p2p_listen_channel=1
#p2p_oper_reg_class=81
#p2p_oper_channel=1
"""

    def _configure(self):
        config = self.base_config
        config += "device_name=" + self.name + "\n"
        config += "p2p_go_intent=%d\n" % self.intent
        self._cmd_or_die("echo -e \"" + config + "\"> /tmp/p2p.conf",
                         verbosity=0)

    def start(self, auto_go=False, client_only=False):
        node.LinuxNode.start(self)
        self._configure()
        self._cmd_or_die("wpa_supplicant -Dnl80211 -c /tmp/p2p.conf -i " +
                         self.iface + " -B")
        time.sleep(1)
        if auto_go and client_only:
            raise UnsupportedConfigurationError(
                "Can't be an auto GO and a client only!")
        if auto_go:
            self._cmd_or_die("wpa_cli p2p_group_add")
        self.auto_go = auto_go
        self.client_only = client_only

    def stop(self):
        node.LinuxNode.stop(self)
        node.LinuxNode.stop(self)
        self.comm.send_cmd("killall wpa_supplicant")
        self.comm.send_cmd("rm -f /var/run/wpa_supplicant/" + self.iface)

    def find_start(self):
        self._cmd_or_die("wpa_cli p2p_find")
        pass

    def find_stop(self):
        self._cmd_or_die("wpa_cli p2p_stop_find")
        pass

    def peers(self):
        # For some reason, the current version of wpa_supplicant returns -1
        # when it finds peers.  Maybe this is a bug?
        [ret, peer_macs] = self.comm.send_cmd("wpa_cli -i " + self.iface +
                                              " p2p_peers")
        peers = []
        for m in peer_macs:
            [ret, pinfo] = self.comm.send_cmd("wpa_cli -i " + self.iface +
                                              " p2p_peer " + m)
            # The first line that is returned is the mac address.  Ignore it.
            pprops = dict(prop.split("=") for prop in pinfo[1:])
            peers.append(Peer(m, pprops['device_name']))
        return peers

    def connect_start(self, peer, method=WPS_METHOD_PBC):
        cmd = "wpa_cli -i " + self.iface + " p2p_connect " + peer.mac
        if method == WPS_METHOD_PBC:
            cmd += " pbc"
        else:
            raise UnimplementedError("Unimplemented WPS method")

        if self.client_only:
            cmd += " join"
        [ret, o] = self.comm.send_cmd(cmd)
        return ret

    def connect_allow(self, peer, method=WPS_METHOD_PBC):
        cmd = "wpa_cli -i " + self.iface + " p2p_connect " + peer.mac
        if method == WPS_METHOD_PBC:
            cmd += " pbc"
        else:
            raise UnimplementedError("Unimplemented WPS method")
        cmd += " auth"
        self._cmd_or_die(cmd)
        return 0

    def pbc_push(self):
        [ret, o] = self.comm.send_cmd("wpa_cli -i " + self.iface +
                                      " wps_pbc")
        return ret

    def connect_finish(self, peer):
        self.comm.send_cmd(
            "echo Waiting for WPS to finish. This may take a while.")
        return node.sta.LinuxSTA._check_auth(self)


class Mvdroid(P2PBase, node.sta.LinuxSTA):

    """
    mvdroid p2p node uses mwu and mwu_cli for p2p negotiation, wps, and wpa
    """

    # This is the hard-coded location where mwu will write the wpa_supplicant
    # config file after becoming a wfd client.
    wpa_conf = "/data/wfd/wpas_wfd.conf"
    wpa_socks = "/tmp/supsocks"

    def __init__(self, comm, iface="wfd0", force_driver_reload=False):
        P2PBase.__init__(self, comm)
        node.LinuxNode.__init__(self, comm, iface, driver=None)
        self.name = comm.name.replace(" ", "-")
        self.force_driver_reload = force_driver_reload

    def load_drivers(self):
        # Ensure the driver is loaded and the interface is available
        [r, o] = self.comm.send_cmd("lsmod | grep sd8xxx")
        if r != 0:
            self._cmd_or_die("insmod /system/lib/modules/mlan.ko")
            self._cmd_or_die("insmod /system/lib/modules/sd8787.ko drv_mode=5")
        self._cmd_or_die("rfkill unblock wifi")
        r = 1
        count = 20
        while r != 0 and count > 0:
            [r, o] = self.comm.send_cmd("ls /sys/class/net/ | grep " +
                                        self.iface)
            count = count - 1
            time.sleep(0.5)
        if r != 0:
            raise node.ActionFailureError("Interface " + self.iface +
                                          " never appeared")

    def unload_drivers(self):
        self.comm.send_cmd("rfkill block wifi")
        self.comm.send_cmd("rmmod sd8xxx")
        self.comm.send_cmd("rmmod mlan")

    def init(self):
        self.comm.send_cmd("killall mwu")
        self.load_drivers()
        (r, self.mac) = self.comm.send_cmd("cat /sys/class/net/" + self.iface +
                                           "/address")
        self.mac = self.mac[0].upper()
        self.intended_mac = self.mac
        node.LinuxNode.init(self)

        cmd = "mwu -c /system/bin/wfd_init.conf -p 00000000 -i " + self.iface
        cmd = cmd + \
            " -d /system/etc/wifidirect_defaults.conf -l /tmp/wfd.log -B"
        self._cmd_or_die(cmd)

        time.sleep(0.1)  # let mwu launch

        # Make sure various directories and files exist or are cleaned up as
        # necessary
        self.comm.send_cmd("mkdir -p /data/wfd; mkdir -p /var/run;")
        self.comm.send_cmd("rm -f " + self.wpa_conf)
        self.comm.send_cmd("mkdir -p " + self.wpa_socks)
        self.comm.send_cmd("chmod 777 " + self.wpa_socks)

    def stop(self):
        if self.force_driver_reload:
            self.comm.send_cmd("killall mwu")
            self.unload_drivers()
            return

        cmd = "mwu_cli module=mwpamod iface=" + self.iface + " cmd=sta_deinit"
        self._cmd_or_die(cmd)
        cmd = "mwu_cli module=mwpsmod iface=" + \
            self.iface + " cmd=registrar_deinit"
        self._cmd_or_die(cmd)
        cmd = "mwu_cli module=mwpamod iface=" + self.iface + " cmd=ap_deinit"
        self._cmd_or_die(cmd)
        cmd = "mwu_cli module=mwpsmod iface=" + \
            self.iface + " cmd=enrollee_deinit"
        self._cmd_or_die(cmd)
        cmd = "mwu_cli module=wifidirect iface=" + self.iface + " cmd=deinit"
        self._cmd_or_die(cmd)
        node.sta.LinuxSTA.stop(self)

    def shutdown(self):
        self.comm.send_cmd("killall mwu")
        self.unload_drivers()
        self.comm.send_cmd("rm -f /tmp/wfd.conf")

    # This is the configuration template for mwu.  Note that it cannot contain
    # the comment (#) character or tab character because these will confuse the
    # comm!
    base_config = '''
wfd_config={
Capability={
DeviceCapability=1
GroupCapability=0
}
GroupOwnerIntent={
Intent=$INTENT
}
Channel={
CountryString=\\"US\\"
RegulatoryClass=81
ChannelNumber=6
}
InfrastructureManageabilityInfo={
Manageability=0
}
ChannelList={
CountryString=\\"US\\"
Regulatory_Class_1=81
NumofChannels_1=3
ChanList_1=1,6,11
}
NoticeOfAbsence={
NoA_Index=0
OppPS=1
CTWindow=10
NoA_descriptor={
CountType_1=255
Duration_1=51200
Interval_1=102400
StartTime_1=0
}
}
DeviceInfo={
DeviceAddress=$MY_MAC
PrimaryDeviceTypeCategory=1
PrimaryDeviceTypeOUI=0x00,0x50,0xF2,0x04
PrimaryDeviceTypeSubCategory=1
SecondaryDeviceCount=2
SecondaryDeviceType={
    SecondaryDeviceTypeCategory_1=6
    SecondaryDeviceTypeOUI_1=0x00,0x50,0xF2,0x04
    SecondaryDeviceTypeSubCategory_1=1
    SecondaryDeviceTypeCategory_2=4
    SecondaryDeviceTypeOUI_2=0x00,0x50,0xF2,0x04
    SecondaryDeviceTypeSubCategory_2=1
}
DeviceName=$NAME
WPSConfigMethods=0x84
}
GroupId={
GroupAddr=$MY_MAC
GroupSsId=\\"WFD_SSID\\"
}
GroupBSSId={
GroupBssId=$MY_MAC
}
DeviceId={
WFD_MAC=$MY_MAC
}
Interface={
InterfaceAddress=$MY_MAC
InterfaceAddressCount=2
InterfaceAddressList=$MY_MAC,00:50:43:78:47:42
}
ConfigurationTimeout={
GroupConfigurationTimeout=100
ClientConfigurationTimeout=150
}
ExtendedListenTime={
AvailabilityPeriod=1000
AvailabilityInterval=1500
}
IntendedIntfAddress={
GroupInterfaceAddress=$MY_MAC
}
OperatingChannel={
CountryString=\\"US\\"
OpRegulatoryClass=81
OpChannelNumber=6
}

WPSIE={
WPSVersion=0x10
WPSSetupState=0x1
WPSRequestType=0x0
WPSResponseType=0x0
WPSSpecConfigMethods=0x0084
WPSUUID=0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78
WPSPrimaryDeviceType=0x01,0x00,0x50,0xF2,0x04,0x01,0x3C,0x10
WPSRFBand=0x01
WPSAssociationState=0x00
WPSConfigurationError=0x00
WPSDevicePassword=0x00
WPSDeviceName=$NAME
WPSManufacturer=\\"Marvell\\"
WPSModelName=\\"88W8787\\"
WPSModelNumber=0x01,0x02,0x03,0x04
WPSSerialNumber=0x01,0x02,0x03,0x11
}
}

wfd_param_config={
MinDiscoveryInterval=1
MaxDiscoveryInterval=3
EnableScan=1
DeviceState=4
}

'''

    def _configure(self):
        config = self.base_config.replace('$INTENT', str(self.intent))
        config = config.replace('$NAME', self.name)
        config = config.replace('$MY_MAC', self.mac)
        self._cmd_or_die("echo -e \"" + config + "\"> /tmp/wfd.conf",
                         verbosity=0)

    def _status_cmd(self, cmd):
        [ret, resp] = self.comm.send_cmd(cmd)
        if ret != 0:
            return ret
        try:
            kvs = resp[0].split(" ")
            if len(kvs) < 1:
                raise node.ActionFailureError(
                    "failed to find kvs in response: " + resp[0])
            for kv in kvs:
                k = kv.split("=")[0]
                v = kv.split("=")[1]
                if k == "status" and v == "0":
                    return 0
                elif k == "status" and v != "0":
                    return int(v)
        except IndexError:
            raise node.ActionFailureError(
                "failed to find kvs in: " + " ".join(resp))

    def _status_cmd_or_die(self, cmd):
        ret = self._status_cmd(cmd)
        if ret != 0:
            raise node.ActionFailureError("bad status: " + str(ret))
        return ret

    def start(self, auto_go=False, client_only=False, config_methods=WPS_METHOD_PBC):
        if auto_go and client_only:
            raise UnsupportedConfigurationError(
                "Can't be an auto GO and a client only!")

        # NOTE: supported config_methods currently buried in the default config
        # values for mwu.  We will eventually be able to change it with the
        # init command.  But for now we ignore it.
        if self.force_driver_reload:
            self.load_drivers()
            self.init()

        cmd = "mwu_cli module=wifidirect iface=" + self.iface + \
              " cmd=init name=" + self.name + " intent=%d" % self.intent
        return self._status_cmd_or_die(cmd)

    def find_start(self):
        cmd = "mwu_cli module=wifidirect iface=" + self.iface + \
              " cmd=start_find"
        return self._status_cmd_or_die(cmd)

    def find_stop(self):
        cmd = "mwu_cli module=wifidirect iface=" + \
            self.iface + " cmd=stop_find"
        self.comm.send_cmd(cmd)

    def peers(self):
        [ret, raw_peers] = self.comm.send_cmd("mwu_cli module=wifidirect iface=" +
                                              self.iface + " cmd=dump_peers")
        peers = []
        index = 0
        while index < len(raw_peers):
            if not raw_peers[index].startswith("device_id="):
                index = index + 1
                continue
            mac = raw_peers[index].split("=")[1]
            name = raw_peers[index + 1].split("=")[1]
            peer = Peer(mac, name)
            peer.intended_mac = raw_peers[index + 5].split("=")[1]
            peers.append(peer)
            index = index + 2
        return peers

    def go_neg_start(self, peer, method=WPS_METHOD_PBC):
        cmd = "mwu_cli module=wifidirect iface=" + self.iface + \
              " cmd=negotiate_group device_id=" + peer.mac
        cmd += " methods=%04X" % method
        self.clear_events()
        return self._status_cmd(cmd)

    def go_neg_finish(self, peer):
        for i in range(1, 30):
            expected = "module=wifidirect iface=" + self.iface + \
                       " event=neg_result"
            event = self.get_next_event()
            eventstr = " ".join(event)
            if eventstr.startswith(expected):
                break

        if not eventstr.startswith(expected):
            return -1

        status = int(event[3].split("=")[1])
        if status != 0:
            return status

        self.is_go = False
        if event[5].split("=")[1] == "true":
            self.is_go = True
            self.ssid = event[6].split("=")[1]
        return 0

    def connect_allow(self, peer, method=WPS_METHOD_PBC):
        cmd = "mwu_cli module=wifidirect iface=" + self.iface + \
              " cmd=allow device_id=" + peer.mac
        cmd += " methods=%04X" % method
        return self._status_cmd(cmd)

    def pdreq(self, peer, method=WPS_METHOD_PBC):
        cmd = "mwu_cli module=wifidirect iface=" + self.iface + \
              " cmd=pd_req device_id=" + peer.mac
        cmd += " methods=%04X" % method
        return self._status_cmd(cmd)

    def pbc_push(self):
        pass

    def registrar_start(self, pin=None):
        # we're the GO.  Launch a registrar
        cmd = "mwu_cli module=mwpsmod iface=" + self.iface
        cmd += " cmd=registrar_init device_name=" + self.name
        cmd += " model_name=wtftester model_number=12345"
        cmd += " methods=%04X" % WPS_METHOD_PBC
        cmd += " ssid=" + self.ssid
        cmd += " auth=0020 encrypt=0008"  # This means wps2psk with AES
        cmd += " key=" + self.key
        ret = self._status_cmd_or_die(cmd)
        if ret != 0:
            return ret
        ret = self._status_cmd_or_die("mwu_cli module=mwpsmod iface=" +
                                      self.iface +
                                      " cmd=registrar_start")
        if ret != 0:
            return ret

        if pin == None:
            return 0

        cmd = "mwu_cli module=mwpsmod iface=" + self.iface
        cmd += " cmd=registrar_set_pin pin=" + pin
        return self._status_cmd_or_die(cmd)

    def ap_start(self, ssid, key):
        cmd = "mwu_cli module=mwpamod iface=" + self.iface
        cmd += " cmd=ap_init ssid=" + ssid
        cmd += " key=" + key
        ret = self._status_cmd(cmd)
        if ret != 0:
            return ret
        ret = self._status_cmd_or_die("mwu_cli module=mwpamod iface=" +
                                      self.iface +
                                      " cmd=ap_start")
        return ret

    def go_start(self):
        # generate a random 32-letter passphrase
        self.key = ''.join(random.choice("0123456789abcdef")
                           for x in range(32))
        ret = self.ap_start(self.ssid, self.key)
        if ret != 0:
            return ret
        return self.registrar_start()

    def do_enrollee(self, registrar):
        cmd = "mwu_cli module=mwpsmod iface=" + self.iface
        cmd += " cmd=enrollee_init device_name=" + self.name
        cmd += " model_name=wtftester model_number=12345"
        cmd += " methods=%04X" % WPS_METHOD_PBC
        ret = self._status_cmd_or_die(cmd)
        if ret != 0:
            return ret
        self.clear_events()
        cmd = "mwu_cli module=mwpsmod iface=" + self.iface
        cmd += " cmd=enrollee_start"
        cmd += " mac=" + registrar
        cmd += " pin="
        ret = self._status_cmd_or_die(cmd)
        if ret != 0:
            return ret

        for i in range(1, 20):
            expected = "module=mwpsmod iface=" + self.iface + \
                       " event=enrollee_done status=0"
            event = self.get_next_event()
            eventstr = " ".join(event)
            if eventstr.startswith(expected):
                break
        if not eventstr.startswith(expected):
            return -1
        self.ssid = event[4].split("=")[1]
        self.key = event[7].split("=")[1]
        return 0

    def do_wpa(self, ssid, key):
        cmd = "mwu_cli module=mwpamod iface=" + self.iface
        cmd += " cmd=sta_init"
        ret = self._status_cmd(cmd)
        if ret != 0:
            return ret
        self.clear_events()
        cmd = "mwu_cli module=mwpamod iface=" + self.iface + " cmd=sta_connect"
        cmd += " ssid=" + ssid + " key=" + key
        ret = self._status_cmd(cmd)
        if ret != 0:
            return ret
        for i in range(1, 4):
            expected = "module=mwpamod event=sta_connect status=0"
            eventstr = " ".join(self.get_next_event())
            if eventstr.startswith(expected):
                break

        if not eventstr.startswith(expected):
            return -1
        return 0

    def get_next_event(self, timeout=2):
        # check for event every half second
        for i in range(0, timeout * 2):
            (r, o) = self.comm.send_cmd(
                "mwu_cli module=mwu cmd=get_next_event")
            if r != 0:
                raise node.ActionFailureError("Failed to get next event")
            if r == 0 and o != []:
                return o
            time.sleep(0.5)
        return o

    def clear_events(self, timeout=2):
        self._cmd_or_die("mwu_cli module=mwu cmd=clear_events")
