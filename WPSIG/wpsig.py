#!/usr/bin/env python
# -*- coding: latin-1 -*-
#
#    WPSIG - WiFi Protected Setup Information Gathering
#    Copyright (C) 2013  Core Security Technologies
#
#    This file is part of WPSIG.
#
#    WPSIG is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WPSIG is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WPSIG.  If not, see <http://www.gnu.org/licenses/>.
#
#    Author: Andrés Blanco 
#
#        ablanco [at coresecurity.com]
#        oss     [at coresecurity.com]

import os
import re
import sys
import random
import struct
import datetime
import optparse


def showMissingLibraryMsg(libraryName, isError=True):
    if isError:
        msgType = "ERROR"
    else:
        msgType = "WARNING"

    print "%s: unable to find %s library." % (msgType, libraryName)
    
    if isError:
        print "Exiting..."
        sys.exit(-1)

# pcapy
try:
    import pcapy
except ImportError:
    showMissingLibraryMsg("pcapy")

# impacket
try:
    from impacket import dot11
    from impacket.dot11 import Dot11
    from impacket.dot11 import Dot11Types
    from impacket.dot11 import Dot11ManagementFrame
    from impacket.dot11 import Dot11ManagementProbeRequest
    from impacket.ImpactDecoder import RadioTapDecoder
except ImportError:
    showMissingLibraryMsg("impacket")

# PyLorcon2
try:
    import PyLorcon2
except ImportError:
    showMissingLibraryMsg("PyLorcon2", isError=False)


def isValidMacAddress(self, address):
    "Return True if it is a valid mac address."
    macAddress = re.compile("^((?:[0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2})$")
    if not macAddress.match(address):
        raise Exception("Invalid MAC Address")
    return True


class Packet(object):
    "Wrapper class for pcapy packet."
    def __init__(self, pkt):
        self.header = pkt[0]
        self.data = pkt[1]
        self.caplen = self.header.getcaplen()
        self.length = self.header.getlen()
        self.timestamp = datetime.datetime.fromtimestamp(self.header.getts()[0])
        self.microseconds = self.header.getts()[1]

    def getHeader(self):
        return self.header

    def getData(self):
        return self.data

    def getCaptureLength(self):
        return self.caplen

    def getLength(self):
        return self.length

    def getTimestamp(self):
        return self.timestamp

    def getMicroseconds(self):
        return self.microseconds

class WpsScanner(object):

    WPS_DATA_ELEMENTS = {
                          0x1001 : "AP Channel",
                          0x1002 : "Association State",
                          0x1003 : "Authentication Type",
                          0x1004 : "Authentication Type Flags",
                          0x1005 : "Authenticator",
                          0x1008 : "Config Methods",
                          0x1009 : "Configuration Error",
                          0x100A : "Confirmation URL4",
                          0x100B : "Confirmation URL6",
                          0x100C : "Connection Type",
                          0x100D : "Connection Type Flags",
                          0x100E : "Credential",
                          0x1011 : "Device Name",
                          0x1012 : "Device Password ID",
                          0x1014 : "E-Hash1",
                          0x1015 : "E-Hash2",
                          0x1016 : "E-SNonce1",
                          0x1017 : "E-SNonce2",
                          0x1018 : "Encrypted Settings",
                          0x100F : "Encryption Type",
                          0x1010 : "Encryption Type Flags",
                          0x101A : "Enrollee Nonce",
                          0x101B : "Feature ID",
                          0x101C : "Identity",
                          0x101D : "Identity Proof",
                          0x101E : "Key Wrap Authenticator",
                          0x101F : "Key Identifier",
                          0x1020 : "MAC Address",
                          0x1021 : "Manufacturer",
                          0x1022 : "Message Type",
                          0x1023 : "Model Name",
                          0x1024 : "Model Number",
                          0x1026 : "Network Index",
                          0x1027 : "Network Key",
                          0x1028 : "Network Key Index",
                          0x1029 : "New Device Name",
                          0x102A : "New Password",
                          0x102C : "OOB Device Password",
                          0x102D : "OS Version",
                          0x102F : "Power Level",
                          0x1030 : "PSK Current",
                          0x1031 : "PSK Max",
                          0x1032 : "Public Key",
                          0x1033 : "Radio Enabled",
                          0x1034 : "Reboot",
                          0x1035 : "Registrar Current",
                          0x1036 : "Registrar Established",
                          0x1037 : "Registrar List",
                          0x1038 : "Registrar Max",
                          0x1039 : "Registrar Nonce",
                          0x103A : "Request Type",
                          0x103B : "Response Type",
                          0x103C : "RF Bands",
                          0x103D : "R-Hash1",
                          0x103E : "R-Hash2",
                          0x103F : "R-SNonce1",
                          0x1040 : "R-SNonce2",
                          0x1041 : "Selected Registrar",
                          0x1042 : "Serial Number",
                          0x1044 : "Wi-Fi Protected Setup State",
                          0x1045 : "SSID",
                          0x1046 : "Total Networks",
                          0x1047 : "UUID-E",
                          0x1048 : "UUID-R",
                          0x1049 : "Vendor Extension",
                          0x104A : "Version",
                          0x104B : "X.509 Certificate Request",
                          0x104C : "X.509 Certificate",
                          0x104D : "EAP Identity",
                          0x104E : "Message Counter",
                          0x104F : "Public Key Hash",
                          0x1050 : "Rekey Key",
                          0x1051 : "Key Lifetime",
                          0x1052 : "Permitted Config Methods",
                          0x1053 : "Selected Registrar Config Methods",
                          0x1054 : "Primary Device Type",
                          0x1055 : "Secondary Device Type List",
                          0x1056 : "Portable Device",
                          0x1057 : "AP Setup Locked",
                          0x1058 : "Application Extension",
                          0x1059 : "EAP Type",
                          0x1060 : "Initialization Vector",
                          0x1061 : "Key Provided Automatically",
                          0x1062 : "802.1X Enabled",
                          0x1063 : "AppSessionKey",
                          0x1064 : "WEPTransmitKey"
                        }

    def __init__(self, interface, filename, macAddress, passiveMode):
        self.__accessPoints = []
        self.__interface = interface
        self.__macAddress = macAddress
        self.__filename = filename
        self.__passive = passiveMode

        self.__context = None
        if not self.__passive:
            try:
                self.__context = PyLorcon2.Context(self.__interface)
                self.__context.open_injmon()
                self.__interface = self.__context.get_capiface()
                self.__filter = "wlan type mgt and " \
                                "(subtype probe-resp or subtype beacon)"
            except Exception, e:
                print "ERROR: exception caught on PyLorcon2."
                raise e
        else:
            self.__filter = "wlan type mgt and subtype probe-resp"

        self.__pd = pcapy.open_live(self.__interface, 65535, 0, 100)
        DLT_IEEE802_11_RADIO = 127
        if self.__pd.datalink() != DLT_IEEE802_11_RADIO:
            print "ERROR: %s is not a 802.11 interface or is not set in " \
                  "monitor mode." % self.__interface
            sys.exit(-1)
        self.__pd.setfilter(self.__filter)

    def __getAddressFromList(self, bytes_list):
        "Return a string of a MAC address on a bytes list."
        return ":".join(map(lambda x: "%02X" % x, bytes_list))

    def __getListFromAddress(self, address):
        "Return a list from a MAC address string."
        return map(lambda x: int(x, 16), address.split(":"))

    def __getVendor(self, address):
        "Return Vendor string for a MAC address using oui.txt."
        db = "oui.txt"
        unknownVendor = "<Unknown Vendor>"
        macAddressRegex = "^((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$"
        ouiLineRegex = "^\s*((?:[0-9A-F]{2}[-]){2}[0-9A-F]{2})\s+\(hex\)\s+(.*)$"
        macAddress = re.compile(macAddressRegex)
        ouiLine = re.compile(ouiLineRegex)
        if not macAddress.match(address):
            raise Exception("Invalid MAC Address")

        address = address.upper()
        if address.find(":") != -1:
            address = "-".join(address.split(":")[:3])
        else:
            address = "-".join(address.split("-")[:3])
        if not os.path.exists(db):
            return unknownVendor

        fd = open(db, "r")
        lines = fd.readlines()
        fd.close()
        for line in lines:
            match = ouiLine.match(line)
            if match:
                addr, vendor = match.groups()
                if address == addr:
                    return vendor

        return unknownVendor

    def __isWPS(self, IEs):
        "Returns True if WPS Information Element is present."
        for element in IEs:
            oui = element[0]
            data = element[1]
            if oui == "\x00\x50\xF2" and data[0] == "\x04": # WPS IE
                return True
        return False

    def __parseWPS(self, IEs):
        "Returns dictionary with WPS Information."
        ret = {}

        for element in IEs:
            offset = 0
            data = element[1]

            offset += 1

            dataLength = len(data)
            while(offset < dataLength):
                tagType = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
                tagLen = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
                tagData = data[offset:offset+tagLen]
                offset += tagLen

                # Get the Tag Type
                if WpsScanner.WPS_DATA_ELEMENTS.has_key(tagType):
                    tagType = WpsScanner.WPS_DATA_ELEMENTS[tagType]
                else:
                    tagType = None

                if tagType == "Wi-Fi Protected Setup State":
                    if tagData == '\x01':
                        tagData = "Not Configured"
                    elif tagData == '\x02':
                        tagData = "Configured"
                    else:
                        tagData = 'Reserved'

                if tagType == "UUID-E":
                    aux = ''
                    for c in tagData:
                        aux += "%02X" % ord(c)
                    tagData = aux

                if tagType == "Response Type":
                    if tagData == '\x00':
                        tagData = 'Enrollee, Info Only'
                    elif tagData == '\x01':
                        tagData = 'Enrollee, open 802.1X'
                    elif tagData == '\x02':
                        tagData = 'Registrar'
                    elif tagData == '\x03':
                        tagData = 'AP'
                    else:
                        tagData = '<unkwon>'

                if tagType == "Primary Device Type":
                    category = struct.unpack("!H", tagData[0:2])[0]
                    subCategory = struct.unpack("!H", tagData[6:8])[0]
                    if category == 1:
                        category = "Computer"
                        if subCategory == 1:
                            subCategory = "PC"
                        elif subCategory == 2:
                            subCategory = "Server"
                        elif subCategory == 3:
                            subCategory = "Media Center"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 2:
                        category = "Input Device"
                        subCategory = "<unkwon>"
                    elif category == 3:
                        category = "Printers, Scanners, Faxes and Copiers"
                        if subCategory == 1:
                            subCategory = "Printer"
                        elif subCategory == 2:
                            subCategory = "Scanner"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 4:
                        category = "Camera"
                        if subCategory == 1:
                            subCategory = "Digital Still Camera"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 5:
                        category = "Storage"
                        if subCategory == 1:
                            subCategory = "NAS"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 6:
                        category = "Network Infrastructure"
                        if subCategory == 1:
                            subCategory = "AP"
                        elif subCategory == 2:
                            subCategory = "Router"
                        elif subCategory == 3:
                            subCategory = "Switch"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 7:
                        category = "Display"
                        if subCategory == 1:
                            subCategory = "Television"
                        elif subCategory == 2:
                            subCategory = "Electronic Picture Frame"
                        elif subCategory == 3:
                            subCategory = "Projector"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 8:
                        category = "Multimedia Devices"
                        if subCategory == 1:
                            subCategory = "DAR"
                        elif subCategory == 2:
                            subCategory = "PVR"
                        elif subCategory == 3:
                            subCategory = "MCX"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 9:
                        category = "Gaming Devices"
                        if subCategory == 1:
                            subCategory = "Xbox"
                        elif subCategory == 2:
                            subCategory = "Xbox360"
                        elif subCategory == 3:
                            subCategory = "Playstation"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 10:
                        category = "Telephone"
                        if subCategory == 1:
                            subCategory = "Windows Mobile"
                        else:
                            subCategory = "<unkwon>"
                    else:
                        category = "<unkwon>"
                        subCategory = "<unkwon>"
                    tagData = "%s - %s" % (category, subCategory)

                    if tagType == "Version":
                        tagData = struct.unpack("B", tagData)[0]
                        major = tagData >> 4
                        minor = tagData & 0x0F 
                        tagData = "%d.%d" % (major, minor)

                    if tagType == "Config Methods":
                        methods = {
                                   0x0001 : "USB",
                                   0x0002 : "Ethernet",
                                   0x0004 : "Label",
                                   0x0008 : "Display",
                                   0x0010 : "External NFC Token",
                                   0x0020 : "Integrated NFC Token",
                                   0x0040 : "NFC Interface",
                                   0x0080 : "PushButton",
                                   0x0100 : "Keypad"
                                  }
                        result = []
                        tagData = struct.unpack("!H", tagData)[0]
                        for key, value in methods.items():
                            if key & tagData:
                                result.append(value)
                        tagData = ", ".join(result)

                if tagType:
                    ret[tagType] = tagData

        return ret

    def scan(self):
        if self.__filename:
            fd = open(self.__filename, "w")
        else:
            fd = None

        try:
            packet = self.__pd.next()
        except Exception:
            packet = None

        while(True):
            if packet:
                data = self.__processPacket(packet, self.__context)
                if data:
                    print data,
                    if fd:
                        fd.write(data)
            try:
                packet = self.__pd.next()
            except Exception:
                packet = None

    def __processBeacon(self, frame):
        "Process 802.11 Beacon Frame for WPS IE."
        packet = Packet(frame)
        data = packet.getData()
        try:
            rtDecoder = RadioTapDecoder()
            rtDecoder.decode(data)
            management = rtDecoder.get_protocol(dot11.Dot11ManagementFrame)
            beacon = rtDecoder.get_protocol(dot11.Dot11ManagementBeacon)
            bssid = self.__getAddressFromList(management.get_bssid())
            essid = beacon.get_ssid()
            if self.__accessPoints.count(bssid) == 0 and \
                self.__isWPS(beacon.get_vendor_specific()):
                src = self.__getListFromAddress(self.__macAddress)
                probe = self.__getProbeRequest(src, essid)
                self.__context.send_bytes(probe)
        except Exception:
            return None

    def __processProbeResponse(self, frame):
        "Process 802.11 Probe Response Frame for WPS IE."
        packet = Packet(frame)
        data = packet.getData()
        try:
            rtDecoder = RadioTapDecoder()
            rtDecoder.decode(data)
            mgt = rtDecoder.get_protocol(dot11.Dot11ManagementFrame)
            probe = rtDecoder.get_protocol(dot11.Dot11ManagementProbeResponse)
            bssid  = self.__getAddressFromList(mgt.get_bssid())
            essid  = probe.get_ssid()
            # If null byte in the SSID IE, its cloacked.
            if essid.find("\x00") != -1:
                essid = "<No ssid>"
            if self.__accessPoints.count(bssid) == 0:
                self.__accessPoints.append(bssid)
                vendorIEs = probe.get_vendor_specific()
                if self.__isWPS(vendorIEs):
                    vendor = self.__getVendor(bssid)
                    wpsInfo = self.__parseWPS(vendorIEs)
                    return [bssid, essid, vendor, wpsInfo]
        except Exception:
            return None

    def __getProbeRequest(self, src, ssid):
        "Return 802.11 Probe Request Frame."
        # Frame Control
        frameControl = Dot11()
        frameControl.set_version(0)
        frameControl.set_type_n_subtype(Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST)
        # Frame Control Flags
        frameControl.set_fromDS(0)
        frameControl.set_toDS(0)
        frameControl.set_moreFrag(0)
        frameControl.set_retry(0)
        frameControl.set_powerManagement(0)
        frameControl.set_moreData(0)
        frameControl.set_protectedFrame(0)
        frameControl.set_order(0)
        # Management Frame
        sequence = random.randint(0, 4096)
        broadcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        mngtFrame = Dot11ManagementFrame()
        mngtFrame.set_duration(0)
        mngtFrame.set_destination_address(broadcast)
        mngtFrame.set_source_address(src)
        mngtFrame.set_bssid(broadcast)
        mngtFrame.set_fragment_number(0)
        mngtFrame.set_sequence_number(sequence)
        # Probe Request Frame
        probeRequestFrame = Dot11ManagementProbeRequest()
        probeRequestFrame.set_ssid(ssid)
        probeRequestFrame.set_supported_rates([0x02, 0x04, 0x0b, 0x16])
        # How is your daddy?
        mngtFrame.contains(probeRequestFrame)
        frameControl.contains(mngtFrame)
        return frameControl.get_packet()

    def __processPacket(self, pkt, context):
        "Process 802.11 Packets."
        packet = Packet(pkt)
        data = packet.getData()
        try:
            rtDecoder = RadioTapDecoder()
            rtDecoder.decode(data)
            beacon = rtDecoder.get_protocol(dot11.Dot11ManagementBeacon)
            probe = rtDecoder.get_protocol(dot11.Dot11ManagementProbeResponse)

            # Process Beacons and inject Probe Requests only when not passive
            if beacon and not self.__passive:
                self.__processBeacon(pkt, context)

            if probe:
                info = self.__processProbeResponse(pkt)
                if info:
                    bssid   = info[0]
                    essid   = info[1]
                    vendor  = info[2]
                    wpsInfo = info[3]
                    result  = "[%s] - '%s'\n" % (bssid, essid)
                    result += "%s (oui.txt vendor)\n" % vendor
                    result += "WPS Information\n"
                    for key, value in wpsInfo.items():
                        result += "  * %s: %s\n" % (key, repr(value))
                    result += "-" * 80
                    result += "\n"
                    return result
        except Exception:
            return None


if __name__ == "__main__":
    print "\nWi-Fi Protected Setup Information Gathering.\n"

    usage = "%prog -i interface -w filename"

    parser = optparse.OptionParser(usage)
    parser.add_option("-i",
                      "--interface",
                      dest="iface",
                      type="string",
                      help="network interface.")
    parser.add_option("-w",
                      "--write",
                      dest="filename",
                      type="string",
                      help="output filename.")
    parser.add_option("-s",
                      "--source",
                      dest="source",
                      type="string",
                      help="source mac address.")
    parser.add_option("-p",
                      "--passive",
                      dest="passive",
                      action="store_true",
                      help="avoid injecting frames.")

    options, args = parser.parse_args()

    # Mandatory Option
    if not options.__dict__["iface"]:
        print "ERROR: iface parameter is missing."
        parser.print_help()
        sys.exit(-1)

    if not os.geteuid() == 0:
        print "ERROR: root privileges are required."
        sys.exit(-1)

    macAddress = None
    passiveMode = True

    if not options.__dict__["passive"] and "PyLorcon2" in globals().keys():
        passiveMode = False
        if options.__dict__["source"]:
            if isValidMacAddress(options.source):
                macAddress = options.source
            else:
                macAddress = "00:00:00:11:22:33"
    else:
        print "WARNING: Using passive mode."

    interface = options.iface
    filename  = options.filename

    ws = WpsScanner(interface, filename, macAddress, passiveMode)
    print "Press Ctrl+C to stop."
    print "Sniffing..."
    print "-" * 80
    try:
        ws.scan()
    except KeyboardInterrupt:
        print "\nCtrl+C caught."
