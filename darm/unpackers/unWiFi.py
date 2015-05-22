from unpacker import *

class UnWiFi (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

	def __str__(self): 
		return "Wi-Fi (802.11x) unpacker"

	def validate(self, packet):
		isValid = False
		try:
			p = packet['payload']
			isValid = p[24:26]=='\xAA\xAA'
		except:
			pass		
		return isValid

	def process(self, packet):
		p = packet['payload']
		packet['top'] = "wifi"
		packet['path'] += ".wifi"
		packet['wifi'] = {}
		packet['wifi']['dst'] = binascii.hexlify(p[4:10])
		packet['wifi']['bssid'] = binascii.hexlify(p[10:16])
		packet['wifi']['src'] = binascii.hexlify(p[16:22])
		packet['wifi']['protocol'] = socket.ntohs(struct.unpack('H',p[30:32])[0])
		packet['payload'] = p[32:]
