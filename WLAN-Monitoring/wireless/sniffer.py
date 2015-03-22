try:
	from scapy.all import *
	from gui.sniff_results import ListResults
	from multiprocessing import Process
	import time, threading, random, Queue
	import signal, os
except ImportError:
	pass
	
class Sniffer(object):
	def __init__(self, q, iface):
		self.iface = iface
		self.queue = q
		'''self.pkts = []
		self.iter = 0
		self.pcapnum = 0'''
		sniff(iface=iface, prn= self.pkt_handler, timeout=0.2)
		
	def pkt_handler(self, p):
		'''self.pkts.append(p)
		self.iter += 1
		if self.iter == 500:
			pname = "pcaps/pcap%d.pcap" % self.pcapnum
			dump = wrpcap(pname, self.pkts)
			if dump:
				print "%s successfully written."
			self.pkts = []
			self.iter = 0
		else:
			wrpcap("pcaps/new.pcap", self.pkts)
		'''
		sess = "Other"
		p.summary()
		if 'Ether' in p:
			if 'IP' in p:
				if 'TCP' in p:
			    		sess = p.sprintf("Ether > IP > TCP %IP.src%:%r,TCP.sport% > %IP.dst%:%r,TCP.dport%")
				elif 'UDP' in p:
				    sess = p.sprintf("Ether > IP > UDP %IP.src%:%r,UDP.sport% > %IP.dst%:%r,UDP.dport%")
				elif 'ICMP' in p:
				    sess = p.sprintf("Ether > IP > ICMP %IP.src% > %IP.dst% type=%r,ICMP.type% code=%r,ICMP.code% id=%ICMP.id%")
				else:
				    sess = p.sprintf("Ether > IP %IP.src% > %IP.dst% proto=%IP.proto%")
			elif 'ARP' in p:
				sess = p.sprintf("Ether > ARP %ARP.psrc% > %ARP.pdst%")
			else:
				sess = p.sprintf("Ether > Ethernet type=%04xr,Ether.type%")
			print sess
	
		elif 'RadioTap' in p:
			if 'Dot11' in p:
				protocol = "802.11"
				frame_type = ""
				if p[Dot11].type==0: frame_type = "Management"
				elif p[Dot11].type==1: frame_type = "Control" 
				subtype = str(p[Dot11].subtype)
				src = p[Dot11].addr2 or p[Dot11].addr3
				dst = p[Dot11].addr1
			
				if 'Dot11Beacon' in p:
					bi = str(p[Dot11Beacon].beacon_interval)
					if 'Dot11Elt' in p:						
						ssid = p[Dot11Elt].info
						sess = "RadioTap / %s %s %s %s > %s / SSID=%s / Beacon Frame, Beacon Interval=%s" % (protocol, frame_type, subtype, src, dst, ssid, bi)
						info = "RadioTap > Beacon Frame, Beacon Interval= %s | Signal: %s dBm" %(bi, str(p[RadioTap].dBm_AntSignal))
						
						#print sess
						msg = [protocol, frame_type, subtype, src, dst, ssid, info]
						self.queue.put(msg)
				elif 'Dot11ProbeReq' in p:
					ssid = p.info
					info = "RadioTap > Probe Request Frame"
					msg = [protocol, frame_type, subtype, src, dst, ssid, info]
					self.queue.put(msg)
						
		#print sess
		
		
	
class ThreadSniffer(object):
	#def __init__(self, parent, iface,):
	def main(self, parent, canvas, iface):
		self.parent = parent
		# assign  Wireless Interface
		self.iface = iface
		
		# Attempt to turn on the interface selected in case it has been down.
		try:
			os.system("sudo ifconfig %s up" % self.iface)
		except OSError:
			pass
			
		# Create the queue
		self.queue = Queue.Queue()
		
		# Set up Gui part
		self.list = ListResults(parent, canvas, self.queue)
		
		self.running = True
		# start a thread to run sniffer
		self.thread1 = threading.Thread(target=self.workerThread1)
		self.thread1.start()
		
		signal.signal(signal.SIGINT, self.stop_sniffer)
		# Start the periodic call in the GUI to check the queue
		self.periodicCall()
		
	def periodicCall(self):
		""" Check every 200 ms if there is something new in the queue. """
		self.parent.after(200, self.periodicCall)
		self.list.processIncoming()
		if not self.running:
			try:
			   	self.thread1.join()
			except e: print e
		
	def workerThread1(self):
		while self.running:
			scan = Sniffer(self.queue, self.iface)
		
	def endApplication(self):
		self.running = False
		self.thread1.join()
		t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
		print "Sniffer stopped at: %s" %t
		
	def stop_sniffer(self,signal, frame):
		self.endApplication()
