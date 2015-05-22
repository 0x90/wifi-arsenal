#!/usr/bin/env python

try:
	from scapy.all import *
	#from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Auth, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, RadioTap
	from gui.tabulate_scan_results import Gui
	from multiprocessing import Process
	import time, threading, random, Queue
	import signal, os
	import scapy_ex
	from Tkinter import Toplevel
except ImportError, e:
	pass

class WifiScanner:
	def __init__(self, q, iface, target):
		self.iface = iface
		self.queue = q
		global networks
		
		self.count = 0
		if target == "AP":
			sniff(iface=iface, lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), timeout=0.2, prn=lambda x: self.add_networks(x) )
			
		elif target == "Client":
			sniff(iface=iface, lfilter= lambda x: (x.haslayer(Dot11ProbeReq) or x.haslayer(Dot11ProbeResp) or x.haslayer(Dot11Auth)), timeout=0.2, prn=lambda x: self.add_stations(x))
			
		elif target == "position":
			sniff(iface=iface, lfilter = lambda x: x.haslayer(RadioTap), timeout=0.2, prn=lambda x: self.get_positions(x))
	
	def get_positions(self, pkt):
		station_mgmt_types = (0,2,4)
		signal = str(pkt[RadioTap].dBm_AntSignal) + " dBm"
		if pkt.type == 0 and pkt.subtype == 8:
			if pkt.addr2 not in networks :
				self.add_networks(pkt)
		elif pkt.type == 0 and pkt.subtype in station_mgmt_types:
			if pkt.addr1 not in networks :
				self.add_stations(pkt)
		else:
			pass
		
	# Function to handle frames related to Access Points and handle their scanned results.
	def add_networks(self, pkt):
		try:
			essid = pkt[Dot11Elt].info if "\x00" not in pkt[Dot11Elt].info and pkt[Dot11Elt].info != '' else 'Hidden SSID'
			channel = int(ord(pkt[Dot11Elt:3].info))
		except IndexError, e:
			print "Error:", e
			return
		self.enc=''
		self.cipher = ''
		self.auth = ''
		bssid = pkt[Dot11].addr3
		signal = str(pkt[RadioTap].dBm_AntSignal) + " dBm"
		if bssid not in networks:
			#known_networks[bssid] = (essid, channel)
			networks.append(bssid)
			enctype = self.getEncType(pkt)
			print "{0:2}\t{1:20}\t{2:20}\t{3:8}\t{4:8}".format(channel, essid, bssid, signal, enctype)
			#msg = "%d %s %s %s" % (channel, essid, bssid, signal)
			msg = ["ap", channel, essid, bssid, signal, enctype, self.iface]
			self.queue.put(msg)
			#self.gui.add_row(channel, signal, bssid, essid)
			
	def getEncType(self, packet):
		if packet.hasflag('cap', 'privacy'):
			elt_rsn = packet[Dot11].rsn()
			if elt_rsn:
				self.enc = elt_rsn.enc
				self.cipher = elt_rsn.cipher
				self.auth = elt_rsn.auth
				return self.enc + "/" + self.cipher + "-" + self.auth
				
			else:
				self.enc = 'WEP'
				self.cipher = 'WEP'
				self.auth = ''
				return self.enc + "/" + self.cipher
		else:
			self.enc = 'OPN'
			self.cipher = ''
			self.auth = ''
			return self.enc
		
	def add_stations(self, pkt):
		self.count += 1
		signal = str(pkt[RadioTap].dBm_AntSignal) + " dBm"
		if pkt.haslayer(Dot11ProbeReq):
			dstmac = pkt.addr1
			mac = pkt.addr2
			if mac not in networks:
				networks.append(mac)
				if pkt.info == "": ssid = "BROADCAST"
				else: ssid = pkt.info
				print "%s is probing %s %s: %s" % (mac,dstmac,ssid, signal)
				msg = ["sta", 0, ssid, mac, signal, "None", self.iface]
				self.queue.put(msg)
		'''
		if pkt.haslayer(Dot11ProbeResp):
			dstmac = pkt.addr1
			bssid = pkt.addr2
			ssid = pkt.info
			print "%s (%s) Probe Response to %s: %s" % (ssid,bssid,dstmac, signal)
		essid = ''
		ap_bssid = ''
		mode = ''
		try:
			essid = pkt[Dot11].essid()
			ap_bssid = pkt[Dot11].ap_bssid()
		except e:
			print e
		if pkt[Dot11].hasflag('FCfield', 'to-DS'):
			mode = pkt[Dot11].hasflag('FCfield', 'pw-mgt')
		print self.count, "\t", essid, "\t", ap_bssid, "\t", mode'''
		
class ThreadedClient(object):
	#def __init__(self, parent, iface, canvas, target):
	def main(self, parent, iface, canvas, target):
		self.parent = parent
		# assign  Wireless Interface
		self.iface = iface
		
		# assign scan target
		self.target = target
			
		# initiate a global variable networks to store obtained networks
		global networks
		networks = []
		
		# Making sure that our wireless interface isn't down.
		try:
			os.system("sudo ifconfig %s up" % self.iface)
		except OSError:
			pass
		
		# Create the queue
		self.queue = Queue.Queue()
		
		# Set up Gui part
		self.gui = Gui(parent, self.queue, self.endApplication, canvas)
		
		self.running = True
		self.multiThreader()

		signal.signal(signal.SIGINT, self.stop_channel_hop)
		# Start the periodic call in the GUI to check the queue
		self.periodicCall()
		
	def multiThreader(self):
		# start a thread to run sniffer
		self.thread1 = threading.Thread(target=self.workerThread1)
		self.thread1.start()
		
		# start a thread to run channel hopper
		self.thread2 = threading.Thread(target=self.channel_hopper, args=(self.iface,))
		self.thread2.start()

	def periodicCall(self):
		""" Check every 200 ms if there is something new in the queue. """
		self.parent.after(200, self.periodicCall)
		self.gui.processIncoming()
		if not self.running:
			try:
			   	self.thread1.join()
			  	self.thread2.join()
			except e: print e
		    
	def workerThread1(self):
		while self.running:
			t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
			#print "Sniffer started at: %s" %t
			scan = WifiScanner(self.queue, self.iface, self.target)
			
	def endApplication(self):
		self.running = False
		t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
		print "Sniffer stopped at: %s" %t
		
	def channel_hopper(self, iface):
		while self.running:
			try:
				channel = random.randrange(1,13)
				os.system("sudo iwconfig %s channel %d" % (iface, channel))
				time.sleep(1.5)
			except KeyboardInterrupt:
				break
				
	def stop_channel_hop(self, signal, frame):
		# calls endApplication function
		self.endApplication()
