import hmac
import hashlib
from core.wireless
from core.wps import WPS
from struct import pack, unpack
from Crypto.Cipher import AES

class WpsCrypto(object):

	# 1536-bit MODP Group from RFC 3526
	prime_strings = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'\
					'29024E088A67CC74020BBEA63B139B22514A08798E3404DD'\
					'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'\
					'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'\
					'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'\
					'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'\
					'83655D23DCA3AD961C62F356208552BB9ED529077096966D'\
					'670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF'
	
	prime_int = int(prime_strings, 16)

	last_msg_buffer = ''
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