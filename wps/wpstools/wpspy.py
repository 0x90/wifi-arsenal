#!/usr/bin/env python

from sys import argv,exit
from getopt import GetoptError,getopt as GetOpt
from time import strftime
from scapy.all import *

class WPS(object):
    verbose = False
    bssid = None
    essid = None
    pfile = None

    #Information element tags
    elTags = {
            'SSID'        : 0,
            'Vendor'     : 221
    }
    #Dictionary of relevent WPS tags and values
    wpsTags = {
                'APLocked'      : {'id' : 0x1057,    'desc' : None},
                'WPSUUID-E'     : {'id' : 0x1047,    'desc' : None},
                'WPSRFBands'    : {'id' : 0x103C,    'desc' : None},
                'WPSRegistrar'  : {'id' : 0x1041,    'desc' : None},
                'WPSState'      : {'id' : 0x1044,    'desc' : {
                                                                0x01 : 'Not Configured',
                                                                0x02 : 'Configured'
                                                              }
                                  },
                'WPSVersion'    : {'id' : 0x104a,    'desc' : {
                                                                0x10 : '1.0',
                                                                0x11 : '1.1'
                                                              }
                                  },
                'WPSRegConfig'  : {'id' : 0x1053,    'desc' : {
                                                                0x0001 : 'USB',
                                                                0x0002 : 'Ethernet',
                                                                0x0004 : 'Label',
                                                                0x0008 : 'Display',
                                                                0x0010 : 'External NFC',
                                                                0x0020 : 'Internal NFC',
                                                                0x0040 : 'NFC Interface',
                                                                0x0080 : 'Push Button',
                                                                0x0100 : 'Keypad'
                                                              },
                                  'action' : 'or'
                                 },
                'WPSPasswordID' : {'id' : 0x1012,    'desc' : {
                                                                0x0000 : 'Pin',
                                                                0x0004 : 'PushButton'
                                                              }
                                  }

    }

    wpsRouters = {}
    wpsClients = {}

    def __init__(self):
        return None

    #Converts an array of bytes ('\x01\x02\x03...') to an integer value
    def strToInt(self,string):
        intval = 0
        shift = (len(string)-1) * 8;

        for byte in string:
            try:
                intval += int(ord(byte))<<shift
                shift -= 8
            except Exception,e:
                print 'Caught exception converting string to int:',e
                return False
        return intval

    #Parse a particular ELT layer from a packet looking for WPS info
    def getWPSInfo(self,elt):
        data = None
        tagNum = elt.ID
        wpsInfo = {}
        minSize = offset = 4
        typeSize = versionSize = 2

        #ELTs must be this high to ride!
        if elt.len > minSize:
            #Loop through the entire ELT
            while offset < elt.len:
                key = ''
                val = ''

                try:
                    #Get the ELT type code
                    eltType = self.strToInt(elt.info[offset:offset+typeSize])
                    offset += typeSize
                    #Get the ELT data length
                    eltLen = self.strToInt(elt.info[offset:offset+versionSize])
                    offset += versionSize
                    #Pull this ELT's data out
                    data = elt.info[offset:offset+eltLen]
                    data = self.strToInt(data)
                except:
                    return False

                #Check if we got a WPS-related ELT type
                for (key,tinfo) in self.wpsTags.iteritems():
                    if eltType == tinfo['id']:
                        if tinfo.has_key('action') and tinfo['action'] == 'or':
                            for method,name in tinfo['desc'].iteritems():
                                if (data | method) == data:
                                    val += name + ' | '
                            val = val[:-3]
                        else:
                            try:
                                val = tinfo['desc'][data]
                            except Exception, e:
                                val = str(hex(data))
                        break


                if key and val:
                    wpsInfo[key] = val
                offset += eltLen
        return wpsInfo

    #Parse captured packets looking for 802.11 WPS-related packets
    def parseCapturedPacket(self,packet):
        wpsInfo = False
        essid = False
        bssid = False

        #Check if the packet is a 802.11 beacon with an ELT layer
        if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt):
            bssid = packet[Dot11].addr3.upper()
            if self.bssid and self.bssid != bssid:
                return
            pkt = packet

            #Loop through all of the ELT layers in the packet
            while Dot11Elt in pkt:
                pkt = pkt[Dot11Elt]

                #Check the ELT layer. Is it a SSID?
                if pkt.ID == self.elTags['SSID']:
                    essid = pkt.info
                    if self.essid and self.essid != essid:
                        return

                #Check the ELT layer. Is it a vendor? If so, try to get the WPS info.
                elif pkt.ID ==  self.elTags['Vendor']:
                    wpsInfo = self.getWPSInfo(pkt)

                #If we've gotten the SSID and WPS info, save it and exit the loop
                if wpsInfo and bssid:
                    #If this is a new SSID, create an entry
                    if not self.wpsRouters.has_key(bssid):
                        self.wpsRouters[bssid] = {}
                    #Only update if the information is new or we're in verbose mode...
                    if self.wpsRouters[bssid] != wpsInfo or self.verbose:
                        self.wpsRouters[bssid] = wpsInfo
                        print 'BSSID:',bssid
                        print 'ESSID:',essid
                        print 'STAMP:',strftime("%H:%M:%S %d/%m/%Y")
                        print '------------------------'
                        for key,val in self.wpsRouters[bssid].iteritems():
                            print key,':',val
                        print '\n'
                    break
                pkt = pkt.payload

    def wpsListener(self):
        if self.verbose:
            if self.pfile:
                print "Reading from %s...\n" % self.pfile
            else:
                print "Listening on %s...\n" % conf.iface
        try:
            sniff(prn=self.parseCapturedPacket,offline=self.pfile)
        except Exception, e:
            print 'Caught exception sniffing packets:',e

def about():
    print '''
WPSpy listens passively to 802.11 beacon packets and examines them for WiFi Protected Setup
information elements. For APs that support WPS, it prints out changes to the AP's WPS status.
    '''
    exit(0)

def usage():
    print '''
Usage: %s [OPTIONS]

    -i <iface>  Specify the interface to use
    -b <bssid>  Filter by BSSID
    -e <essid>  Filter by ESSID
    -p <file>   Load pcap file
    -v          Enable verbose mode
    -a          Display about information
    -h          Display help
''' % argv[0]
    exit(1)

def main():
    wps = WPS()

    try:
        opts,args = GetOpt(argv[1:],'i:b:e:p:ahv')
    except GetoptError, e:
        print 'ERROR:',e
        usage()

    for (opt,optarg) in opts:
        if opt == '-h':
            usage()
        elif opt == '-a':
            about()
        elif opt == '-v':
            wps.verbose = True
        elif opt == '-i':
            conf.iface = optarg
        elif opt == '-b':
            wps.bssid = optarg.upper()
        elif opt == '-e':
            wps.essid = optarg
        elif opt == '-p':
            wps.pfile = optarg
        else:
            usage()

    print ''
    wps.wpsListener()



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print 'Bye!'
