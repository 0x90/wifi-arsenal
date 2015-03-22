#!/usr/bin/python
from scapy.all import *
import time
import random
import binascii
import hashlib
import datetime
import sys
import monitor_mode 
import random

ssid="helloWorld"
f=open('log_traffic.txt','w')
rand_ssid = True

words=[]
if rand_ssid:
    f2=open('words.txt')
    words=f2.readlines()
    words = [x.rstrip() for x in words]

def rand_mac():
    return ':'.join(map(lambda x: "%02x" % x, [ 0x00, 0x16, 0x3E, random.randint(0x00, 0x7F), random.randint(0x00, 0xFF), random.randint(0x00, 0xFF) ]))

def generate_new_macs(num):
    """Generate random mac address list"""
    tmp_mac_addresses=[]
    for i in range(num):
        tmp_mac_addresses.append(rand_mac())
    return tmp_mac_addresses

def make_traffic(num_macs=10, run_time=30, cull=0.9,iface="mon0"):
        assert(num_macs > 0)
        assert(cull <= 1.0)
        assert(run_time > 0)
        mac_addresses = {}
        packet_counter = 0
        cycle_count = 0
        mac_counter = {}
        num_to_remove = int(cull * num_macs)
        print "[+] Good day, sir. I will send probe request traffic from %d unique MAC addresses cycling %d of them every %s" %(num_macs,num_to_remove,str(datetime.timedelta(seconds=run_time)))
        while True:            
            if mac_addresses:
                for i in range( num_to_remove ):
                    mac_addresses.pop()
                mac_addresses = mac_addresses + generate_new_macs(num_to_remove)
                #mac_counter += num_to_remove
            else:
                mac_addresses = generate_new_macs(num_macs)
            start_time = int(os.times()[4])
            current_time = start_time
            while start_time + run_time > current_time:
                random.shuffle(mac_addresses)
                for mac in mac_addresses:
                     mac_counter[mac] = 1
                     print "\r[+] Sent a total of %d packets from %d unique MAC addresses so far (cycled MACs %d times)" % (packet_counter, len(mac_counter), cycle_count),
                     sys.stdout.flush()
                     if rand_ssid:
                        rnd = random.randint(0,len(words)-1)
                        ssid = words[rnd]
                     p=RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff', addr3='ff:ff:ff:ff:ff:ff',addr2=mac)/Dot11ProbeReq() / Dot11Elt(ID='SSID', info=ssid) 
                     for i in range(random.randint(3,5)):
                          sendp(p, iface=iface, verbose=0)
                          packet_counter += 1
                current_time = int(os.times()[4])
                time.sleep(5)
            cycle_count+=1
            time.sleep(0.4)            

def main():
    iface = monitor_mode.enable_monitor_mode()        
    make_traffic(200, 2*60, 0.8,iface) #Generate N macs, traffic for 30 minutes, then generate new macs with 90% overlap

if __name__ == "__main__":
    main()
