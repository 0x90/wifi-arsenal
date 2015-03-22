from .eap import *
from rpyutils import *
from .constants import *

from scapy.layers.dot11 import *
from scapy.layers.dhcp import *
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP


class Callbacks(object):
    def __init__(self, ap):
        self.ap = ap

        self.cb_recv_pkt = self.recv_pkt
        self.cb_dot11_probe_req = self.dot11_probe_resp
        self.cb_dot11_beacon = self.dot11_beacon
        self.cb_dot11_auth = self.dot11_auth
        self.cb_dot11_ack = self.dot11_ack
        self.cb_dot11_assoc_req = self.dot11_assoc_resp
        self.cb_dot11_rts = self.dot11_cts

        self.cb_dot1X_eap_req = self.dot1x_eap_resp

        self.cb_arp_req = self.arp_resp

        self.cb_dhcp_discover = self.dot11_to_tint
        self.cb_dhcp_request = self.dot11_to_tint
        self.cb_dns_request = self.dot11_to_tint
        self.cb_other_request = self.dot11_to_tint

        self.cb_tint_read = self.recv_pkt_tint

    def recv_pkt(self, packet):
        try:
            if len(packet.notdecoded[8:9]) > 0:  # Driver sent radiotap header flags
                # This means it doesn't drop packets with a bad FCS itself
                flags = ord(packet.notdecoded[8:9])
                if flags & 64 != 0:  # BAD_FCS flag is set
                    # Print a warning if we haven't already discovered this MAC
                    if not packet.addr2 is None:
                        printd("Dropping corrupt packet from %s" % packet.addr2, Level.BLOAT)
                    # Drop this packet
                    return

            # Management
            if packet.type == DOT11_TYPE_MANAGEMENT:
                if packet.subtype == DOT11_SUBTYPE_PROBE_REQ:  # Probe request
                    if Dot11Elt in packet:
                        ssid = packet[Dot11Elt].info

                        printd("Probe request for SSID %s by MAC %s" % (ssid, packet.addr2), Level.DEBUG)

                        # Only send a probe response if one of our own SSIDs is probed
                        if ssid in self.ap.ssids or (Dot11Elt in packet and packet[Dot11Elt].len == 0):
                            if not (self.ap.hidden and ssid != self.ap.get_ssid()):
                                self.cb_dot11_probe_req(packet.addr2, self.ap.get_ssid())
                elif packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # Authentication
                    if packet.addr1 == self.ap.mac:  # We are the receivers
                        self.ap.sc = -1  # Reset sequence number
                        self.cb_dot11_auth(packet.addr2)
                elif packet.subtype == DOT11_SUBTYPE_ASSOC_REQ or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ:
                    if packet.addr1 == self.ap.mac:
                        self.cb_dot11_assoc_req(packet.addr2, packet.subtype)

                        # After association, start EAP session if enabled
                        if self.ap.ieee8021x:
                            self.cb_dot1X_eap_req(packet.addr2, EAPCode.REQUEST, EAPType.IDENTITY, None)

            # Data packet
            if packet.type == DOT11_TYPE_DATA:
                if EAPOL in packet:
                    if packet.addr1 == self.ap.mac:
                        # EAPOL Start
                        if packet[EAPOL].type == 0x01:
                            self.ap.eap.reset_id()
                            self.dot1x_eap_resp(packet.addr2, EAPCode.REQUEST, EAPType.IDENTITY, None)
                if EAP in packet:
                    if packet[EAP].code == EAPCode.RESPONSE:  # Responses
                        if packet[EAP].type == EAPType.IDENTITY:
                            identity = str(packet[Raw])
                            if packet.addr1 == self.ap.mac:
                                # EAP Identity Response
                                printd("Got identity: " + identity[0:len(identity) - 4], Level.INFO)

                            # Send auth method LEAP
                            self.dot1x_eap_resp(packet.addr2, EAPCode.REQUEST, EAPType.EAP_LEAP, "\x01\x00\x08" + "\x00\x00\x00\x00\x00\x00\x00\x00" + str(identity[0:len(identity) - 4]))
                        if packet[EAP].type == EAPType.NAK:  # NAK
                            method = str(packet[Raw])
                            method = method[0:len(method) - 4]
                            method = ord(method.strip("x\\"))
                            printd("NAK suggested method " + EAPType.convert_type(method), Level.INFO)

                elif ARP in packet:
                    if packet[ARP].pdst == self.ap.ip.split('/')[0]:
                        self.cb_arp_req(packet.addr2, packet[ARP].psrc)
                elif DHCP in packet:
                    if packet.addr1 == self.ap.mac:
                        if packet[DHCP].options[0][1] == 1:
                            self.cb_dhcp_discover(packet)

                        if packet[DHCP].options[0][1] == 3:
                            self.cb_dhcp_request(packet)
                elif DNS in packet:
                    self.cb_dns_request(packet)
                elif IP in packet:
                    self.cb_other_request(packet)

        except Exception as err:
            print("Unknown error at monitor interface: %s" % repr(err))

    def recv_pkt_tint(self, packet):
        try:
            packet = IP(packet)  # We expect an IP packet from the external interface
            if BOOTP in packet:
                client_mac = bytes_to_mac(packet[BOOTP].chaddr[:6])

                if DHCP in packet and packet[DHCP].options[0][1] == 5:  # DHCP ACK
                    client_ip = packet[BOOTP].yiaddr
                    self.ap.arp.add_entry(client_ip, client_mac)
                    printd("IP %s -> %s" % (client_ip, client_mac), Level.INFO)

                # Forward our message to the client
                self.dot11_encapsulate_ip(client_mac, packet)
            else:
                client_ip = packet[IP].dst
                self.dot11_encapsulate_ip(self.ap.arp.get_entry(client_ip), packet)

        except Exception as err:
            print("Unknown error at tun interface: %s" % repr(err))

    def dot11_probe_resp(self, source, ssid):
        probe_response_packet = self.ap.get_radiotap_header() \
                                / Dot11(subtype=5, addr1=source, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                                / Dot11ProbeResp(timestamp=self.ap.current_timestamp(), beacon_interval=0x0064, cap=0x2104) \
                                / Dot11Elt(ID='SSID', info=ssid) \
                                / Dot11Elt(ID='Rates', info=AP_RATES) \
                                / Dot11Elt(ID='DSset', info=chr(self.ap.channel))

        # If we are an RSN network, add RSN data to response
        if self.ap.ieee8021x:
            probe_response_packet[Dot11ProbeResp].cap = 0x3101
            rsn_info = Dot11Elt(ID='RSNinfo', info=RSN)
            probe_response_packet = probe_response_packet / rsn_info

        sendp(probe_response_packet, iface=self.ap.interface, verbose=False)

    def dot11_beacon(self, ssid):
        # Create beacon packet
        beacon_packet = self.ap.get_radiotap_header()                                                    \
                     / Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=self.ap.mac, addr3=self.ap.mac) \
                     / Dot11Beacon(cap=0x2105)                                                           \
                     / Dot11Elt(ID='SSID', info=ssid)                                                    \
                     / Dot11Elt(ID='Rates', info=AP_RATES)                                               \
                     / Dot11Elt(ID='DSset', info=chr(self.ap.channel))

        if self.ap.ieee8021x:
            beacon_packet[Dot11Beacon].cap = 0x3101
            rsn_info = Dot11Elt(ID='RSNinfo', info=RSN)
            beacon_packet = beacon_packet / rsn_info

        # Update sequence number
        beacon_packet.SC = self.ap.next_sc()

        # Update timestamp
        beacon_packet[Dot11Beacon].timestamp = self.ap.current_timestamp()

        # Send
        sendp(beacon_packet, iface=self.ap.interface, verbose=False)

    def dot11_auth(self, receiver):
        auth_packet = self.ap.get_radiotap_header() \
                      / Dot11(subtype=0x0B, addr1=receiver, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                      / Dot11Auth(seqnum=0x02)

        printd("Sending Authentication (0x0B)...", Level.DEBUG)
        sendp(auth_packet, iface=self.ap.interface, verbose=False)

    def dot11_ack(self, receiver):
        ack_packet = self.ap.get_radiotap_header() \
                     / Dot11(type='Control', subtype=0x1D, addr1=receiver)

        print("Sending ACK (0x1D) to %s ..." % receiver)
        sendp(ack_packet, iface=self.ap.interface, verbose=False)

    def dot11_assoc_resp(self, receiver, reassoc):
        response_subtype = 0x01
        if reassoc == 0x02:
            response_subtype = 0x03
        assoc_packet = self.ap.get_radiotap_header() \
                       / Dot11(subtype=response_subtype, addr1=receiver, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                       / Dot11AssoResp(cap=0x2104, status=0, AID=self.ap.next_aid()) \
                       / Dot11Elt(ID='Rates', info=AP_RATES)

        printd("Sending Association Response (0x01)...", Level.DEBUG)
        sendp(assoc_packet, iface=self.ap.interface, verbose=False)

    def dot11_cts(self, receiver):
        cts_packet = self.ap.get_radiotap_header() \
                     / Dot11(ID=0x99, type='Control', subtype=12, addr1=receiver, addr2=self.ap.mac, SC=self.ap.next_sc())

        printd("Sending CTS (0x0C)...", Level.DEBUG)
        sendp(cts_packet, iface=self.ap.interface, verbose=False)

    def arp_resp(self, receiver_mac, receiver_ip):
        arp_packet = self.ap.get_radiotap_header() \
                     / Dot11(type="Data", subtype=0, addr1=receiver_mac, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc(), FCfield='from-DS') \
                     / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
                     / SNAP(OUI=0x000000, code=ETH_P_ARP) \
                     / ARP(psrc=self.ap.ip.split('/')[0], pdst=receiver_ip, op="is-at", hwsrc=self.ap.mac, hwdst=receiver_mac)

        printd("Sending ARP Response...", Level.DEBUG)
        sendp(arp_packet, iface=self.ap.interface, verbose=False)

    def dot1x_eap_resp(self, receiver, eap_code, eap_type, eap_data):
        eap_packet = self.ap.get_radiotap_header() \
                     / Dot11(type="Data", subtype=0, addr1=receiver, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc(), FCfield='from-DS') \
                     / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
                     / SNAP(OUI=0x000000, code=0x888e) \
                     / EAPOL(version=1, type=0) \
                     / EAP(code=eap_code, id=self.ap.eap.next_id(), type=eap_type)

        if not eap_data is None:
            eap_packet = eap_packet / Raw(eap_data)

        printd("Sending EAP Packet (code = %d, type = %d, data = %s)..." % (eap_code, eap_type, eap_data), Level.DEBUG)
        sendp(eap_packet, iface=self.ap.interface, verbose=False)

    def unspecified_raw(self, raw_data):
        raw_packet = Raw(raw_data)

        printd("Sending RAW packet...", Level.DEBUG)
        sendp(raw_packet, iface=self.ap.interface, verbose=False)

    def dhcp_offer(self, client_mac, client_ip, xid):
        dhcp_offer_packet = self.ap.get_radiotap_header() \
                            / Dot11(type="Data", subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=self.ap.mac, SC=self.ap.next_sc(), FCfield='from-DS') \
                            / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
                            / SNAP(OUI=0x000000, code=ETH_P_IP) \
                            / IP(src=self.ap.ip, dst=client_ip) \
                            / UDP(sport=67, dport=68) \
                            / BOOTP(op=2, yiaddr=client_ip, siaddr=self.ap.ip, giaddr=self.ap.ip, chaddr=mac_to_bytes(client_mac), xid=xid) \
                            / DHCP(options=[('message-type', 'offer')]) \
                            / DHCP(options=[('subnet_mask', '255.255.255.0')]) \
                            / DHCP(options=[('server_id', self.ap.ip), 'end'])

        sendp(dhcp_offer_packet, iface=self.ap.interface, verbose=False)

    def dhcp_ack(self, client_mac, client_ip, xid):
        dhcp_ack_packet = self.ap.get_radiotap_header() \
                          / Dot11(type="Data", subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=self.ap.mac, SC=self.ap.next_sc(), FCfield='from-DS') \
                          / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
                          / SNAP(OUI=0x000000, code=ETH_P_IP) \
                          / IP(src=self.ap.ip, dst=client_ip) \
                          / UDP(sport=67,dport=68) \
                          / BOOTP(op=2, yiaddr=client_ip, siaddr=self.ap.ip, giaddr=self.ap.ip, chaddr=mac_to_bytes(client_mac), xid=xid) \
                          / DHCP(options=[('message-type','ack')]) \
                          / DHCP(options=[('server_id', self.ap.ip)]) \
                          / DHCP(options=[('lease_time', 43200)]) \
                          / DHCP(options=[('subnet_mask', '255.255.255.0')]) \
                          / DHCP(options=[('router', self.ap.ip)]) \
                          / DHCP(options=[('name_server', DEFAULT_DNS_SERVER)]) \
                          / DHCP(options=[('domain', "localdomain")]) \
                          / DHCP(options=['end'])
        sendp(dhcp_ack_packet, iface=self.ap.interface, verbose=False)

    def dot11_encapsulate_ip(self, client_mac, ip_packet):
        if IP in ip_packet:
            del ip_packet[IP].chksum
            del ip_packet[IP].len
        else:
            raise Exception("Attempted to encapsulate non-IP packet.")

        if UDP in ip_packet:
            del ip_packet[UDP].len

        response_packet = self.ap.get_radiotap_header() \
                          / Dot11(type="Data", subtype=0, addr1=client_mac, addr2=self.ap.mac, SC=self.ap.next_sc(), FCfield='from-DS') \
                          / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
                          / SNAP(OUI=0x000000, code=ETH_P_IP) \
                          / Raw(ip_packet)

        sendp(response_packet, iface=self.ap.interface, verbose=False)

    def dot11_to_tint(self, pkt):
        self.ap.tint.write(pkt)  # Pass to third party application for handling