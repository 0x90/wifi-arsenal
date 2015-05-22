import sys
import socket
import time
try:
	import pcapy
except:
	print 'This script requires pcapy. (apt-get install python-pcapy)'
	sys.exit(-1)
from reporters import DNSReporter

class Source:
	__unpacker = []

	def __init__(self):
		self.__seq = 0
		self.dumpfile = None

	def setUnpacker(self, unpacker):
		self.__unpacker = unpacker

	def analyze_packet(self, header, data):
		self.__seq += 1
		if not data:
			return

		info = {}
		info['caplen'] = header.getcaplen()
		info['totallen'] = header.getlen()
		info['timestamp'] = header.getts()
		info['seq'] = self.__seq		

		packet = {}
		packet['top'] = 'raw'
		packet['path'] = 'raw'
		packet['raw'] = info
		packet['payload'] = data
		self.__unpacker.addPacket(packet)

	def runFromFile(self, filename):
		reader = None		
		try:
			reader = pcapy.open_offline(filename)
		except:
			print "Could not open file {0}.".format(filename)
			sys.exit(-1)
		else:
			self.__run(reader)			
		
	def runLive(self, interface):
		reader = None		
		try:
			reader = pcapy.open_live(interface, 1600, 0, 100)
		except:
			print "Invalid interface or insufficient permissions."
			sys.exit(-1)
		else:
			self.__run(reader)			

	def __showSummaries(self, isPartialSummary):
		
			if (isPartialSummary):
				print "Partial summary: "
			else:
				print "Final summary: "
			DNSReporter().summaryReport()
				

	def __run(self, reader):			
		dumper = None
		if not self.dumpfile is None:
			print "Dumping output to {0}".format(self.dumpfile)
			dumper = reader.dump_open(self.dumpfile)

		totalTime = time.time()
		packet_count = 0
		byteCount = 0

		lastNotificationTime = time.time()
		lastPacketCount = 0
		lastByteCount = 0
		timeThreshold = 5
		wasForcefullyInterrupted = False
		
		try:
			while 1:
				try:
					packet = reader.next()
				except socket.timeout:
					pass
				else:
					if not packet[0] is None:
						packet_count += 1
						apply(self.analyze_packet, packet)
						if not dumper is None:
							apply(dumper.dump, packet)
						byteCount += packet[0].getcaplen()
					else:
						break;

				if time.time()-lastNotificationTime>timeThreshold:
					pps = float(packet_count-lastPacketCount) / timeThreshold
					KBps = float((byteCount-lastByteCount) / timeThreshold) / 1024
					print("Analyzing packets (%.2f pps, %.2f KB/s)..." % (pps, KBps))
					lastNotificationTime = time.time()
					lastPacketCount = packet_count
					lastByteCount = byteCount

		except KeyboardInterrupt:
			wasForcefullyInterrupted = True
			
		del reader
		totalTime = time.time() - totalTime
		print '\n%d packets analyzed in %.3f secs (%f pp)' % (packet_count, totalTime, totalTime/packet_count)
		self.__unpacker.close()

		self.__showSummaries(wasForcefullyInterrupted)
