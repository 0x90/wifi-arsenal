from scapy.all import *
import csv
import sys

file = open(sys.argv[1], 'wb')
writer = csv.writer(file, delimiter=',')

def packet(pkt):
  if pkt.haslayer(Dot11):
    if pkt.type == 0 and pkt.subtype == 8:
      if pkt.info == 'aalto open': # SSID to be surveyed.
        print pkt.show2()
        channel = pkt.notdecoded[10:12] # Channel derived from 802.11 frame RadioTAP headers. Location might change if using another WiFi card/drivers.
        channel = struct.unpack('h', channel)[0]
        print "%s %s %s Mhz %s" % (pkt.info, pkt.addr2, channel, -(256-ord(pkt.notdecoded[14]))) # More RadioTAP data.
        writer.writerow([pkt.info, pkt.addr2, channel, -(256-ord(pkt.notdecoded[14]))]) # More RadioTAP data.

sniff(iface="mon0", prn = packet, timeout=4) # Interface for 802.11 frame capture



