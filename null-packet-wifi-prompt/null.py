import sys

from scapy.all import *
from datetime import datetime

DATA_TYPE=2
NULL_SUBTYPE=36
ACK_SUBTYPE=29

channel=1
MIN_CHANNEL=1
MAX_CHANNEL=11

def send_null_packet(iface,DEST_MAC,SRC_MAC):
    p = RadioTap()/Dot11(type=DATA_TYPE,subtype=NULL_SUBTYPE,addr1=DEST_MAC,addr2=SRC_MAC) 
    conf.iface = iface
    sendp(p)

def set_channel(iface,c):
    import os
    print ("Setting channel to %s"%c)
    os.system("iw dev %s set channel %s"%(iface,c))
    
def main():
    print "[%s] Sending null frames"%datetime.now()
    iface = sys.argv[1]
    DEST_MAC = sys.argv[2]
    SRC_MAC = sys.argv[3]
    channel=MIN_CHANNEL
    while 1:
        send_null_packet(iface,DEST_MAC,SRC_MAC)
        channel+=1
        if channel>MAX_CHANNEL:
            channel=MIN_CHANNEL
        set_channel(iface,channel)

if __name__=="__main__":
    main()
