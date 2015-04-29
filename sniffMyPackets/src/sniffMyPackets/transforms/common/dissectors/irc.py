from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
import dissector


class IRCResField(StrField):
    """
    field class for handling irc responses
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "IRCResField"

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
        value = ""
        ls = s.split("\r\n")
        length = len(ls)
        if length == 1:
            return "", value
        elif length > 1:
                value = ""
                value = value + "response: " + ls[0]
                i = 1
                while i < length - 1:
                    value = value + " response: " + ls[i]
                    if i < length - 2:
                        value = value + " | "
                    i = i + 1
                return "", value
        else:
            return "", ""

    def __init__(self, name, default, fmt, remain=0):
        """
        class constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class IRCReqField(StrField):
    """
    field class for handling irc requests
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "IRCReqField"

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
        remain = ""
        value = ""
        ls = s.split()
        length = len(ls)
        if length > 1:
            value = "command: " + ls[0] + ","
            if length == 2:
                remain = ls[1]
                value = value + " Parameters: " + remain
                return "", value
            else:
                i = 1
                remain = ""
                while i < length:
                    if i != 1:
                        remain = remain + " " + ls[i]
                    else:
                        remain = remain + ls[i]
                    i = i + 1
                value = value + " Parameters: " + remain
                return "", value
        else:
            return "", ls[0]

    def __init__(self, name, default, fmt, remain=0):
        """
        class constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class IRCRes(Packet):
    """
    class for handling irc responses
    @attention: it inherets Packet from Scapy library
    """
    name = "irc"
    fields_desc = [IRCResField("response", "", "H")]


class IRCReq(Packet):
    """
    class for handling irc requests
    @attention: it inherets Packet from Scapy library
    """
    name = "irc"
    fields_desc = [IRCReqField("command", "", "H")]

bind_layers(TCP, IRCReq, dport=6660)
bind_layers(TCP, IRCReq, dport=6661)
bind_layers(TCP, IRCReq, dport=6662)
bind_layers(TCP, IRCReq, dport=6663)
bind_layers(TCP, IRCReq, dport=6664)
bind_layers(TCP, IRCReq, dport=6665)
bind_layers(TCP, IRCReq, dport=6666)
bind_layers(TCP, IRCReq, dport=6667)
bind_layers(TCP, IRCReq, dport=6668)
bind_layers(TCP, IRCReq, dport=6669)
bind_layers(TCP, IRCReq, dport=7000)
bind_layers(TCP, IRCReq, dport=194)
bind_layers(TCP, IRCReq, dport=6697)


bind_layers(TCP, IRCRes, sport=6660)
bind_layers(TCP, IRCRes, sport=6661)
bind_layers(TCP, IRCRes, sport=6662)
bind_layers(TCP, IRCRes, sport=6663)
bind_layers(TCP, IRCRes, sport=6664)
bind_layers(TCP, IRCRes, sport=6665)
bind_layers(TCP, IRCRes, sport=6666)
bind_layers(TCP, IRCRes, sport=6667)
bind_layers(TCP, IRCRes, sport=6668)
bind_layers(TCP, IRCRes, sport=6669)
bind_layers(TCP, IRCRes, sport=7000)
bind_layers(TCP, IRCRes, sport=194)
bind_layers(TCP, IRCRes, sport=6697)
