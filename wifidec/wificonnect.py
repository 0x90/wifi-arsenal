import subprocess, os


def connectOpen(SSID, APMAC, interface):
	"""iwconfig wlan0 key 'mykey' mode managed essid 'mychannel' channel integer ap 00:00:00:00:00:00"""
	subprocess.check_output(["iwconfig", interface, "mode", "managed", "essid", "'"+SSID+"'", "channel", channel, "ap", APMAC])


def connectWpa(SSID, passkey, interface):
	outconf = subprocess.check_output(["wpa_passphrase", SSID, passkey])
	
	#outconf = "network={\n"
	#outconf += "ssid=\"" + SSID + "\"\n"
	#outconf += "scan_ssid=1\n"
	#outconf += "key_mgmt=WPA-PSK\n"
	#outconf += "psk=\"" + passkey + "\"\n"
	#outconf += "}\n"
	#save in a file in cwd :: os.getcwd()
	fo = open("wpasup.conf", "w+")
	fo.write( outconf )
	fo.close()

	fpath = os.path.join(os.getcwd(), "wpasup.conf")
	return subprocess.Popen(["wpa_supplicant", "-c"+fpath, "-i"+interface])
	
