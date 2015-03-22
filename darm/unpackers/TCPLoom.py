import sys
from common import *
from analyzers import *

class TCPLoom:
	
	def __init__(self):
		self.__threads = []
		self.__index = {}
		self.__fullCount = 0
		self.__currentCount = 0

	def __findThread(self, packet):		
		src_ip = packet['ip']['src']
		dst_ip = packet['ip']['dst']
		src_port = packet['tcp']['src']
		dst_port = packet['tcp']['dst']
		t1 = (src_ip, src_port, dst_ip, dst_port)
		try:
			idx = self.__index[t1]
			return self.__threads[idx]
		except:
			return None
	
	def __openThread(self, packet):
		src_ip = packet['ip']['src']
		dst_ip = packet['ip']['dst']
		src_port = packet['tcp']['src']
		dst_port = packet['tcp']['dst']		
		t1 = (src_ip, src_port, dst_ip, dst_port)
		t2 = (dst_ip, dst_port, src_ip, src_port)

		idx = len(self.__threads)
		self.__index[t1] = idx		
		self.__index[t2] = idx		

		thread = {}
		thread['data'] = ""
		thread['src'] = src_ip #"{0}({1})".format(src_ip, KnownPorts().tcp(src_port))
		thread['dst'] = dst_ip #"{0}({1})".format(dst_ip, KnownPorts().tcp(dst_port))
		thread['state'] = 'open'
		thread['size'] = 0		
		thread['seq'] = self.__fullCount		 
		self.__threads += [thread]

		self.__fullCount += 1
		self.__currentCount += 1
		Log.write("New TCP thread (#{0})".format(idx),2) 
		return thread		

	def __closeThread(self, thread, state):		
		if thread['state'] == 'open':
			# dump thread content to file if user requested it
			if CommandLine().cfg['tcp_dumpthreads']:
				self.__saveThread(thread)
			# close analyzer if there's one
			TCPAnalyzers().closeAnalyzers(thread)
			# change state and delete data from memory
			thread['state'] = state		
			thread['data'] = ""
			self.__currentCount -= 1
		
	def __appendToThread(self, thread, packet):
		p = packet['payload']
		plen = len(p)
		if plen>0:
			thread['data'] += p
			thread['size'] += plen
			TCPAnalyzers().analyzeData(thread)

	def __saveThread(self, thread):
		if thread['size']>0:
			filename = "{0}-{1}.data".format(thread['src'], thread['dst'])
			Log.write("Dumping TCP thread #{0} as '{1}' ({2} bytes)".format(thread['seq'], filename, thread['size']), 2)
			fh = open(filename,"wb")
			fh.write(thread['data'])
			fh.close()
		else:
			Log.write("Discarding empty TCP thread #{0} {1}-{2}".format(thread['seq'], thread['src'], thread['dst']), 2)
		
	def addPacket(self, packet):
		thread = self.__findThread(packet)
		if thread is None:
			thread = self.__openThread(packet)

		flags = packet['tcp']['flags']
		self.__appendToThread(thread, packet)

		if ("F" in flags) and ("A" in flags):
			self.__closeThread(thread, "closed")
			Log.write("TCP thread #{0} closed.".format(thread['seq']), 2)
		elif "R" in flags:
			self.__closeThread(thread, "resetted")
			Log.write("TCP thread #{0} resetted!".format(thread['seq']), 2)

	def close(self):
		for thread in self.__threads:
			if thread['state']=="open":
				Log.write("TCP Thread #{0} capture interrupted!".format(thread['seq']), 2)
				self.__closeThread(thread, "interrupted")		
		print "{0} TCP threads analyzed".format(self.__fullCount)
		del self.__threads

