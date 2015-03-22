from unpacker import *

class UnIP (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

	def __str__(self): 
		return "IP unpacker"

	def validate(self, packet):
		isValid = False
		try:
			isValid = packet[packet['top']]['protocol'] == 0x0800
		except:
			pass
		return isValid

	def process(self, packet):
		p = packet['payload']
		packet['top'] = "ip"
		packet['path'] += ".ip"
		packet['ip'] = {}
		packet['ip']['protocol'] = ord(p[9])
		packet['ip']['src'] = socket.inet_ntoa(p[12:16])
		packet['ip']['dst'] = socket.inet_ntoa(p[16:20])
		packet['payload'] = p[20:]
