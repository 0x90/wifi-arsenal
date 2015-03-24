#!/usr/bin/env python
import subprocess, sys, re, time, random, argparse

from subprocess import call, Popen, PIPE
from argparse import ArgumentParser

parser = ArgumentParser(description='KARMA honeypot.')
parser.add_argument('-i', metavar='interface', action="store", default=False, help='wireless interface', required=True)
args = parser.parse_args()

interface = args.i
intmon="mon0"
essid="badkarma"
mac=""
words = [line.strip() for line in open('/etc/dictionaries-common/words')]
def log(text):
	"This prints info to screen."
	print "[!] " + text
	return;

def runcommand(command1):
	"This runs a command."

	Temp=Popen(command1.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
	(output,errput)=Temp.communicate()
	return_value=Temp.wait()
	return errput + output;
def runmdk3_nowait(command1):
	"This runs a command and does not wait for or capture output."
	with open ("mdk3.log", "w+") as out, open("stderr.txt", "w+") as err:
		Popen(command1.split(),stdout=out,stdin=None,stderr=err)
	return;
def getmoninterface(input):
	for line in input.split('\n'):
        	if "monitor mode enabled on" in line:
			tmp=line.rsplit(None, 1)
               		tmpmon=tmp[-1].strip()[:-1]
			intmon=tmpmon.strip()
			log ("Monitor active on interface " + intmon)
	return intmon;
def setstage():
	"This sets up required interfaces, etc"
	log("Stopping network-manager..")
	runcommand("service network-manager stop")
	log("Starting monitor interface..")
	output=runcommand("airmon-ng start " + interface)
	if "monitor mode enabled on" in output:
		intmon=getmoninterface(output)
		runcommand("touch blacklist")
	else:
		log (output)
		sys.exit(-1)
	return;
def readmdk3():
	with open ("mdk3.log", "rU") as myfile:
		for line in myfile:
			if "Disconnecting between: " in line:
				log ("Liberation! " + line.strip())
	return
def printnewmac(input):
	for line in input.split('\n'):
		if "New       MAC: " in line:
			newmac=re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', line, re.I).group()
			log ("Wireless MAC is now " + newmac)
	return;
def createSSID():
	"This creates a fake ssid and tries to connect. If successful, returns true"
	word1="'"
	word2="'"
	while "'" in word1:
		word1=(random.choice(words))
	while "'" in word2:
		word2=(random.choice(words))
	essid=word1+word2
	log ("ESSID is now " + essid)
	output=runcommand ("mv blacklist blacklist-wait")
	output=runcommand ("ifconfig " + interface + " down")
	if "No such device" in output:
        	log (output)
	        log ("Exiting...")
		sys.exit(-1)
	else:
		output=runcommand ("macchanger -r " + interface)
		printnewmac(output)
		output=runcommand("iwconfig " + interface + " essid " + essid)
		output=runcommand("ifconfig " + interface + " up")
		output=runcommand("mv blacklist-wait blacklist")
	return;
def lookforjoin():
	"This checks iwconfig for mac indicating join"
	output=runcommand ("iwconfig " + interface)
	a = 0
	while a < 10:
		try:
			mac=re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', output, re.I).group()
			log("Bad AP " + mac + " found! Adding to blacklist...")
			with open('blacklist', 'a+') as file:
				file.write(mac)
				file.write('\n')
				file.close()
			runcommand ("sort -u blacklist")
			break
		except:
			output=runcommand ("iwconfig " + interface)
			time.sleep(1)
			mac=""
			a = a + 1
def killAP():
	runcommand("pkill mdk3")
	output=runmdk3_nowait("mdk3 " + intmon + " d -b blacklist")
	return;

def cleanup():
	log("Deleting blacklist...")
	runcommand("rm blacklist")
	log("Ending deauth...")
	runcommand("pkill mdk3")
	log("Stopping monitor interface " + intmon)
	runcommand("airmon-ng stop " + intmon)
	log("Resetting interface " + interface)
	runcommand("ifconfig " + interface + " down")
	runcommand("iwconfig " + interface + " essid any")
	runcommand("ifconfig " + interface + " up")
	log("Starting network-manager...")
	runcommand("service network-manager start")
	return;

output=runcommand ("ifconfig " + interface);

if "Device not found" in output:#
	log ("Device not found: " + interface)
	log ("Exiting...")
	sys.exit(-1)
else:
	try:
		setstage();
		time.sleep(3);
		while True:
			createSSID();
			killAP();
			lookforjoin();
			time.sleep(10);
			readmdk3();
	except KeyboardInterrupt:
		log ("Cleaning Up...")
		cleanup();
		log ("Exiting..")
		sys.exit(0);
