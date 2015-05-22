import base64
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
from scapy.layers.dns import *
import dissector


class SIPStartField(StrField):
    """
    field class for handling sip start field
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "SIPStartField"

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
        ls = s.splitlines(True)
        f = ls[0].split()
        if "SIP" in f[0]:
            ls = s.splitlines(True)
            f = ls[0].split()
            length = len(f)
            value = ""
            if length == 3:
                value = "SIP-Version:" + f[0] + ", Status-Code:" +\
                f[1] + ", Reason-Phrase:" + f[2]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            else:
                value = ls[0]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            return remain, value
        elif "SIP" in f[2]:
            ls = s.splitlines(True)
            f = ls[0].split()
            length = len(f)
            value = []
            if length == 3:
                value = "Method:" + f[0] + ", Request-URI:" +\
                f[1] + ", SIP-Version:" + f[2]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            else:
                value = ls[0]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            return remain, value
        else:
            return s, ""


class SIPMsgField(StrField):
    """
    field class for handling the body of sip packets
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "SIPMsgField"
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
        if s.startswith("\r\n"):
            s = s.lstrip("\r\n")
            if s == "":
                return "", ""
        self.myresult = ""
        for c in s:
            self.myresult = self.myresult + base64.standard_b64encode(c)
        return "", self.myresult


class SIPField(StrField):
    """
    field class for handling the body of sip fields
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "SIPField"

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
        if self.name == "unknown-header(s): ":
            remain = ""
            value = []
            ls = s.splitlines(True)
            i = -1
            for element in ls:
                i = i + 1
                if element == "\r\n":
                    return s, []
                elif element != "\r\n" and (": " in element[:10])\
                 and (element[-2:] == "\r\n"):
                    value.append(element)
                    ls.remove(ls[i])
                    remain = ""
                    unknown = True
                    for element in ls:
                        if element != "\r\n" and (": " in element[:15])\
                         and (element[-2:] == "\r\n") and unknown:
                            value.append(element)
                        else:
                            unknow = False
                            remain = remain + element
                    return remain, value
            return s, []

        remain = ""
        value = ""
        ls = s.splitlines(True)
        i = -1
        for element in ls:
            i = i + 1
            if element.upper().startswith(self.name.upper()):
                value = element
                value = value.strip(self.name)
                ls.remove(ls[i])
                remain = ""
                for element in ls:
                    remain = remain + element
                return remain, value[len(self.name) + 1:]
        return s, ""

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


class SIP(Packet):
    """
    class for handling the body of sip packets
    @attention: it inherets Packet from Scapy library
    """
    name = "sip"
    fields_desc = [SIPStartField("start-line: ", "", "H"),
                   SIPField("accept: ", "", "H"),
                   SIPField("accept-contact: ", "", "H"),
                   SIPField("accept-encoding: ", "", "H"),
                   SIPField("accept-language: ", "", "H"),
                   SIPField("accept-resource-priority: ", "", "H"),
                   SIPField("alert-info: ", "", "H"),
                   SIPField("allow: ", "", "H"),
                   SIPField("allow-events: ", "", "H"),
                   SIPField("authentication-info: ", "", "H"),
                   SIPField("authorization: ", "", "H"),
                   SIPField("call-id: ", "", "H"),
                   SIPField("call-info: ", "", "H"),
                   SIPField("contact: ", "", "H"),
                   SIPField("content-disposition: ", "", "H"),
                   SIPField("content-encoding: ", "", "H"),
                   SIPField("content-language: ", "", "H"),
                   SIPField("content-length: ", "", "H"),
                   SIPField("content-type: ", "", "H"),
                   SIPField("cseq: ", "", "H"),
                   SIPField("date: ", "", "H"),
                   SIPField("error-info: ", "", "H"),
                   SIPField("event: ", "", "H"),
                   SIPField("expires: ", "", "H"),
                   SIPField("from: ", "", "H"),
                   SIPField("in-reply-to: ", "", "H"),
                   SIPField("join: ", "", "H"),
                   SIPField("max-forwards: ", "", "H"),
                   SIPField("mime-version: ", "", "H"),
                   SIPField("min-expires: ", "", "H"),
                   SIPField("min-se: ", "", "H"),
                   SIPField("organization: ", "", "H"),
                   SIPField("p-access-network-info: ", "", "H"),
                   SIPField("p-asserted-identity: ", "", "H"),
                   SIPField("p-associated-uri: ", "", "H"),
                   SIPField("p-called-party-id: ", "", "H"),
                   SIPField("p-charging-function-addresses: ", "", "H"),
                   SIPField("p-charging-vector: ", "", "H"),
                   SIPField("p-dcs-trace-party-id: ", "", "H"),
                   SIPField("p-dcs-osps: ", "", "H"),
                   SIPField("p-dcs-billing-info: ", "", "H"),
                   SIPField("p-dcs-laes: ", "", "H"),
                   SIPField("p-dcs-redirect: ", "", "H"),
                   SIPField("p-media-authorization: ", "", "H"),
                   SIPField("p-preferred-identity: ", "", "H"),
                   SIPField("p-visited-network-id: ", "", "H"),
                   SIPField("path: ", "", "H"),
                   SIPField("priority: ", "", "H"),
                   SIPField("privacy: ", "", "H"),
                   SIPField("proxy-authenticate: ", "", "H"),
                   SIPField("proxy-authorization: ", "", "H"),
                   SIPField("proxy-require: ", "", "H"),
                   SIPField("rack: ", "", "H"),
                   SIPField("reason: ", "", "H"),
                   SIPField("record-route: ", "", "H"),
                   SIPField("referred-by: ", "", "H"),
                   SIPField("reject-contact: ", "", "H"),
                   SIPField("replaces: ", "", "H"),
                   SIPField("reply-to: ", "", "H"),
                   SIPField("request-disposition: ", "", "H"),
                   SIPField("require: ", "", "H"),
                   SIPField("resource-priority: ", "", "H"),
                   SIPField("retry-after: ", "", "H"),
                   SIPField("route: ", "", "H"),
                   SIPField("rseq: ", "", "H"),
                   SIPField("security-client: ", "", "H"),
                   SIPField("security-server: ", "", "H"),
                   SIPField("security-verify: ", "", "H"),
                   SIPField("server: ", "", "H"),
                   SIPField("service-route: ", "", "H"),
                   SIPField("session-expires: ", "", "H"),
                   SIPField("sip-etag: ", "", "H"),
                   SIPField("sip-if-match: ", "", "H"),
                   SIPField("subject: ", "", "H"),
                   SIPField("subscription-state: ", "", "H"),
                   SIPField("supported: ", "", "H"),
                   SIPField("timestamp: ", "", "H"),
                   SIPField("to: ", "", "H"),
                   SIPField("unsupported: ", "", "H"),
                   SIPField("user-agent: ", "", "H"),
                   SIPField("via: ", "", "H"),
                   SIPField("warning: ", "", "H"),
                   SIPField("www-authenticate: ", "", "H"),
                   SIPField("refer-to: ", "", "H"),
                   SIPField("history-info: ", "", "H"),
                   SIPField("unknown-header(s): ", "", "H"),
                   SIPMsgField("message-body: ", "")]

bind_layers(TCP, SIP, sport=5060)
bind_layers(TCP, SIP, dport=5060)
bind_layers(UDP, SIP, sport=5060)
bind_layers(UDP, SIP, dport=5060)
