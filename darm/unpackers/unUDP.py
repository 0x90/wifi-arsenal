from unpacker import *

class UnUDP (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

	def __str__(self): 
		return "UDP unpacker"

	def validate(self, packet):
		isValid = False
		try:
			isValid = packet['ip']['protocol'] == socket.IPPROTO_UDP
		except:
			pass
		return isValid

	def process(self, packet):
		p = packet['payload']
		packet['top'] = "udp"
		packet['path'] += ".udp"
		packet['udp'] = {}
		packet['udp']['src'] = socket.ntohs(struct.unpack('H',p[0:2])[0])
		packet['udp']['dst'] = socket.ntohs(struct.unpack('H',p[2:4])[0])
		packet['payload'] = p[8:]

	def close(self):
		Unpacker.close(self)
