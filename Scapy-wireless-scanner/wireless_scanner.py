#Implementation of a wireless scanner using Scapy library

#!/usr/bin/env python
# rs.py - Wireless AP scanner 
#author rahil sharma
# date 15/3/2013   @rs
#usage python rs.py mon0
#where mon0 is your monitoring interface
#used this using my alfa card in bactrack
import sys, os, signal 
from multiprocessing import Process

from scapy.all import *

interface='' # monitor interface
aps = {} # dictionary to store unique APs

# process unique sniffed Beacons and ProbeResponses. 
#haslayer packet has Dot11 layer present
#ord() string to integer ex ord('a) will give 97
def sniffAP(p):
    if ( (p.haslayer(Dot11Beacon))):
        ssid       = p[Dot11Elt].info
        bssid      = p[Dot11].addr3    
        channel    = int( ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Check for encrypted networks
	#now we put Dot11Beacon.cap info in capability and using regular expression search inbuilt function in python we search for privacy if it is present then the network is encrypted
	#output of the above cap file is somewhat like this short-slot+DSSS-OFDM+res15+ESS
        if re.search("privacy", capability): enc = 'Y'
        else: enc  = 'N'

        # Save discovered AP
        aps[p[Dot11].addr3] = enc

        # Display discovered AP    
        print "%02d  %s  %s %s" % (int(channel), enc, bssid, ssid) 

# Channel hopper - we are making a channel hopper because we want to scan the whole wireless spectrum.
#first choose a random channel using randrange function
#use system to run the shell command iw dev wlan0 set channel 1
#exit when a keyboard interrupt is given CTrl+c
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,15)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break
            # Capture interrupt signal and cleanup before exiting
#terminate is used to end the child process
#before exiting the program we will be displaying number of aps found etc.
#here Cntrl+c is used to 
#signal_handler used to do clean up before the program exits
def signal_handler(signal, frame):
    p.terminate()
    p.join()

    print "\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-"
    print "Total APs found: %d" % len(aps)
    print "Encrypted APs  : %d" % len([ap for ap in aps if aps[ap] =='Y'])
    print "Unencrypted APs: %d" % len([ap for ap in aps if aps[ap] =='N'])

    sys.exit(0)
#use this for command line variables 
#for checking the number of command line variables and if they are in right order
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s monitor_interface" % sys.argv[0]
        sys.exit(1)

    interface = sys.argv[1]
#take mon0 as interface given in the fist command line variable
    # Print the program header
    print "-=-=-=-=-=-= rs_scan.py =-=-=-=-=-=-"
    print "CH ENC BSSID             SSID"

    # Start the channel hopper
    #In multiprocessing, processes are spawned by creating a Process object and then calling its start() method
    p = Process(target = channel_hopper)
    p.start()

    # Capture CTRL-C 
    #this will call the signal handler CTRL+C comes under the SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # Start the sniffer
    sniff(iface=interface,prn=sniffAP)
    #inbuit scapy function to start sniffing calls a function which defines the criteria and we need to give the interface
