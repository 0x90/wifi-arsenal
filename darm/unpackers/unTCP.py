from unpacker import *
from TCPLoom import *

class UnTCP (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)
		self.__loom = TCPLoom()

	def __str__(self): 
		return "TCP unpacker"

	def validate(self, packet):
		isValid = False
		try:
			isValid = packet['ip']['protocol'] == socket.IPPROTO_TCP
		except:
			pass
		return isValid

	def __updatePacketInfo(self, packet):
		p = packet['payload']
		packet['top'] = "tcp"
		packet['path'] += ".tcp"
		packet['tcp'] = {}
		packet['tcp']['src'] = socket.ntohs(struct.unpack('H',p[0:2])[0])
		packet['tcp']['dst'] = socket.ntohs(struct.unpack('H',p[2:4])[0])
#		packet['tcp']['seq'] = socket.ntohl(struct.unpack('I',p[4:8])[0])

		flagsValue = ord(p[13])
		flags = ""
		if flagsValue & 0x01: flags += "F"
		if flagsValue & 0x02: flags += "S"
		if flagsValue & 0x04: flags += "R"
		if flagsValue & 0x08: flags += "P"
		if flagsValue & 0x10: flags += "A"
		packet['tcp']['flags'] = flags

		dataOffset = (ord(p[12]) & 0xF0) >> 4
		packet['payload'] = p[dataOffset*4:]

	def process(self, packet):
		self.__updatePacketInfo(packet)
		self.__loom.addPacket(packet)

	def close(self):
		self.__loom.close()
		Unpacker.close(self)
