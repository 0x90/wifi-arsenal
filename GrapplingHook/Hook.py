### GRAPPLING HOOK - HOOK MODULE
### HOOK parses the signal strength from target clients CTS packets
### Displays as received signal strength indicated (RSSI) in dB


from scapy.all import *
import pcap
import optparse
from time import sleep
import sys

def ctscap(p):
    if p.haslayer(Dot11):
        if p.type == 1 and p.subtype == 12 and p.addr1 == receiveclient: #Its a CTS frame headed to your capture tool
            rssi = -(256-ord(p.notdecoded[-4:-3])) #Strips signal strength from RADIOTAP Hex Header
            sys.stdout.write('\r')
            sys.stdout.write("RSSI of Target= "+str(rssi))
            sys.stdout.flush()
def main():
    parser = optparse.OptionParser('usage%prog '+'-r <receiveclient> -i <interface>')
    parser.add_option('-r', dest='receiveclient', type='string', help='specify listener MAC address')
    parser.add_option('-i', dest='interface', type='string', help='specify receive interface')
    (options, args) = parser.parse_args()
    global receiveclient
    receiveclient = options.receiveclient
    global interface
    interface = options.interface   
   
    sniff(iface=interface, prn=ctscap) #Begin SCAPY sniffer and apply function "ctscap" to every packet

if __name__ == '__main__':
    main()
