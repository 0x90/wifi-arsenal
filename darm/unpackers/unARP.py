from unpacker import *

class UnARP (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

	def __str__(self): 
		return "ARP unpacker"

	def _packetInfo(self, packet):
		seq = packet['raw']['seq']
		sha = packet['arp']['sha']
		spa = packet['arp']['spa']
		tpa = packet['arp']['tpa']
		path = packet['path']
		if packet['arp']['op'] == "request":
			return "#{0} {1} Who has {2}? Tell {3}".format(seq, path, tpa, spa)
		else:
			return "#{0} {1} {2} is at {3}".format(seq, path, spa, sha)

	def validate(self, packet):
		isValidParent = packet['top'] in ['eth', 'wifi']		
		isValid = False
		try:
			isValid = isValidParent and (packet[packet['top']]['protocol'] == 0x0806)
		except:
			pass		
		return isValid

	def process(self, packet):
		p = packet['payload']

		d = {}
		d['htype'] = socket.ntohs(struct.unpack('H',p[0:2])[0]) 
		d['ptype'] = socket.ntohs(struct.unpack('H',p[2:4])[0])
		hlen = ord(p[4])
		plen = ord(p[5])
		d['op'] = socket.ntohs(struct.unpack('H',p[6:8])[0])
		d['op'] = 'request' if d['op']==1 else 'reply' if d['op']==2 else 'unknown'

		i = 8
		d['sha'] = p[i:i+hlen]
		i += hlen
		d['spa'] = p[i:i+plen]
		i += plen
		d['tha'] = p[i:i+hlen]
		i += hlen
		d['tpa'] = p[i:i+plen]

		if (hlen==6) and (plen==4):
			# we'll assume this is ARP for IPv4
			d['sha'] = binascii.hexlify(d['sha'])
			d['tha'] = binascii.hexlify(d['tha'])
			d['spa'] = socket.inet_ntoa(d['spa'])
			d['tpa'] = socket.inet_ntoa(d['tpa'])	

		packet['top'] = "arp"
		packet['path'] += ".arp"
		packet['arp'] = d

