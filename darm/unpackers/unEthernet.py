from unpacker import *

class UnEthernet (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

	def __str__(self): 
		return "Ethernet unpacker"

	def validate(self, packet):
		isValid = False
		try:
			# find out a way to properly identify ethernet frames
			p = packet['payload']
			seg = p[26:28]
			isValid = (len(seg)==2) and (seg!='\xAA\xAA')
		except:
			pass
		return isValid

	def process(self, packet):
		p = packet['payload']
		packet['top'] = "eth"
		packet['path'] += ".eth"
		packet['eth'] = {}
		packet['eth']['dst']=binascii.hexlify(p[0:6])
		packet['eth']['src']=binascii.hexlify(p[6:12])
		packet['eth']['protocol']=socket.ntohs(struct.unpack('H',p[12:14])[0])
		packet['payload'] = p[14:]
