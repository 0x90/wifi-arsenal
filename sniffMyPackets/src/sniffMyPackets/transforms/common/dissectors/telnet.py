import base64
from scapy.packet import *
from scapy.utils import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
import dissector


class TELNETField(XByteField):
    """
    field class for handling the telnet packets
    @attention: this class inherets XByteField
    """
    holds_packets = 1
    name = "TELNETField"
    myresult = ""

    def __init__(self, name, default):
        """
        class constructor, for initializing instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        """
        self.name = name
        self.fmt = "!B"
        Field.__init__(self, name, default, "!B")

    def get_code_msg(self, cn):
        """
        method returns a message for every a specific code number
        @param cn: code number
        """
        codes = {0: "TRANSMIT-BINARY", 1: "ECHO",
                  3: "SUPPRESS-GO-AHEAD",
                  5: "STATUS", 6: "TIMING-MARK",
                   7: "RCTE", 10: "NAOCRD",
                  11: "NAOHTS", 12: "NAOHTD",
                   13: "NAOFFD", 14: "NAOVTS",
                  15: "NAOVTD", 16: "NAOLFD",
                   17: "EXTEND-ASCII",
                   18: "LOGOUT", 19: "BM", 20: "DET", 21: "SUPDUP",
                   22: "SUPDUP-OUTPUT", 23: "SEND-LOCATION",
                  24: "TERMINAL-TYPE", 25: "END-OF-RECORD",
                  26: "TUID", 27: "OUTMRK", 28: "TTYLOC", 29: "3270-REGIME",
                  30: "X.3-PAD", 31: "NAWS", 32: "TERMINAL-SPEED",
                  33: "TOGGLE-FLOW-CONTROL", 34: "LINEMODE",
                   35: "X-DISPLAY-LOCATION",
                  36: "ENVIRON", 37: "AUTHENTICATION", 38: "ENCRYPT",
                  39: "NEW-ENVIRON", 40: "TN3270E", 44: "COM-PORT-OPTION",
                  236: "End of Record", 237: "Suspend Current Process",
                  238: "Abort Process", 239: "End of File", 240: "SE",
                  241: "NOP", 242: "Data Mark", 243: "Break",
                  244: "Interrupt Process", 245: "Abort output",
                  246: "Are You There", 247: "Erase character",
                  248: "Erase Line", 249: "Go ahead", 250: "SB", 251: "WILL",
                  252: "WON'T", 253: "DO", 254: "DON'T", 255: "Command"}
        if cn in codes:
            return codes[cn] + " "
        return "UnknownCode[" + str(cn) + "] "

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        cstream = -1
        if pkt.underlayer.name == "TCP":
            cstream = dissector.check_stream(\
                    pkt.underlayer.underlayer.fields["src"],\
                     pkt.underlayer.underlayer.fields["dst"],\
                      pkt.underlayer.fields["sport"],\
                       pkt.underlayer.fields["dport"],\
                        pkt.underlayer.fields["seq"], s)
        if not cstream == -1:
            s = cstream
        self.myresult = ""
        subOptions = False
        resultlist = []
        firstb = struct.unpack(self.fmt, s[0])[0]
        if firstb != 255:
            self.myresult = ""
            for c in s:
                self.myresult = self.myresult + base64.standard_b64encode(c)
            return  "", "data " + self.myresult

        for c in s:
            ustruct = struct.unpack(self.fmt, c)
            command = self.get_code_msg(ustruct[0])
            if command == "SB ":
                subOptions = True
                self.myresult = self.myresult + "SB "
                continue
            if command == "SE ":
                subOptions = False
                self.myresult = self.myresult = self.myresult + "SE "
                continue
            if subOptions:
                self.myresult = self.myresult +\
                 "subop(" + str(ustruct[0]) + ") "
                continue
            else:
                self.myresult = self.myresult + command
        comlist = self.myresult.split("Command ")
        for element in comlist:
            if element != "":
                resultlist.append(("command", element))
        #return  "", resultlist
        return  "", self.myresult


class TELNET(Packet):
    """
    field class for handling the telnet packets
    @attention: this class inherets Packet
    """
    name = "telnet"
    fields_desc = [TELNETField("telnetpayload", "")]

bind_layers(TCP, TELNET, dport=23)
bind_layers(TCP, TELNET, sport=23)
"""
pkts = rdpcap("/root/Desktop/telnet-cooked.pcap")
for pkt in pkts:
    pkt.show()
"""
