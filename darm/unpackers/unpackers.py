from unpacker import *
from unEthernet import *
from unWiFi import *
from unIP import *
from unTCP import *
from unUDP import *
from unDNS import *
from unARP import *

class Unpackers:

	def __init__(self):

		# layer 5 (application)
		uDNS = UnDNS()

		# layer 4 (transport)
		uUDP = UnUDP()
		uUDP.addUnpacker(uDNS)
		
		uTCP = UnTCP()

		# layer 3 (network)		
		uIP = UnIP()
		uIP.addUnpacker(uTCP)
		uIP.addUnpacker(uUDP)

		# layer 2 (data link)
		uARP = UnARP()

		# layer 1 (physical)
		uEthernet = UnEthernet()
		uEthernet.addUnpacker(uIP)
		uEthernet.addUnpacker(uARP)

		uWiFi = UnWiFi()
 		uWiFi.addUnpacker(uIP)
 		uWiFi.addUnpacker(uARP)

		# unpackers graph starting node
		root = Unpacker()
		root.addUnpacker(uWiFi)
		root.addUnpacker(uEthernet) # can't detect this, so it behaves like default option
		self.__root = root

	def getRoot(self):
		return self.__root
