from scapy.all import *
import time

accessPoints = {}
devices = {}

def printNumActiveDevices():
    # counts the number of devices that have been around in
    # the past 5 minutes
    currentEpochTime = int(time.time())
    numActive = 0
    for ssid in devices:
        diff = currentEpochTime - devices[ssid]
        if ( diff < 300 ):
            numActive += 1

    print("# Devices: " + str(numActive))

def addMACtoAPList(ssid, mac):
    # check to see if we have already added the access point
    # if we have, then check to see if the current MAC is in
    # the list of MAC addresses associated with that ap
    if ssid in accessPoints:
        macList = accessPoints[ssid]
        if mac in macList:
            return
        else:
            macList.append(mac)
    else:
        accessPoints[ssid] = [mac]

# sniff all 802.11 beacons and store in a list
def sniffDot11Beacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        # get the 802.11 layer and the information element layer
        dot11Layer = pkt.getlayer(Dot11)
        beaconElt = pkt.getlayer(Dot11Elt)[0]

        # get the MAC address and ssid
        macAddr = dot11Layer.addr2
        ssid = beaconElt.info

        # put into list
        addMACtoAPList(ssid, macAddr)
    elif pkt.haslayer(Dot11):
        # get the 802.11 layer and pull the MAC address
        dot11Layer = pkt.getlayer(Dot11)

        # get the current time
        currentEpochTime = int(time.time())

        # add the MAC address to the list of devices if it already
        # isn't in there, otherwise update time we last saw it
        macAddr = dot11Layer.addr2
        if macAddr not in devices:
            devices[macAddr] = currentEpochTime
        else:
            devices[macAddr] = currentEpochTime

        printNumActiveDevices()



sniff(iface='mon0', prn=sniffDot11Beacon)
