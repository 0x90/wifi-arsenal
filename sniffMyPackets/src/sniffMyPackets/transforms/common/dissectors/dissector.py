import json # json formatting module
import binascii # this class to handle the hex/ascii converting
from scapy.all import Packet, rdpcap, ConditionalField, Emph, conf
'''
imported files from Scapy library
'''
from scapy.layers.dot11 import *
from scapy.layers.ir import *
from scapy.layers.ppp import *
from scapy.layers.gprs import *
from scapy.layers.mobileip import *
from scapy.layers.smb import *
from scapy.layers.bluetooth import *
from scapy.layers.isakmp import *
from scapy.layers.radius import *
from scapy.layers.hsrp import *
from scapy.layers.netbios import *
from scapy.layers.snmp import *
from scapy.layers.dhcp6 import *
from scapy.layers.l2 import *
from scapy.layers.rip import *
from scapy.layers.inet6 import *
from scapy.layers.netflow import *
from scapy.layers.tftp import *
from scapy.layers.dhcp import *
from scapy.layers.l2tp import *
from scapy.layers.rtp import *
from scapy.layers.inet import *
from scapy.layers.ntp import *
from scapy.layers.x509 import *
from scapy.layers.dns import *
from scapy.layers.llmnr import *
from scapy.layers.sebek import *
from scapy.layers.pflog import *
from scapy.layers.dot11 import *
from scapy.layers.mgcp import *
from scapy.layers.skinny import *
'''
import the protocols classes
'''
from ftp import *
from http import *
from imap import *
from irc import *
from pop import *
from sip import *
from smtp import *
from ssh import *
from telnet import *


def is_created_session(Src, Dst, SPort, DPort):
    """
    this method is used for purpose of tcp stream reassemble,
    for checking if this is a new session of not.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    """
    i = 0
    while i < len(dissector.Dissector.preprocess_sessions):
        if  Src == dissector.Dissector.preprocess_sessions[i][0]\
         and Dst == dissector.Dissector.preprocess_sessions[i][1]\
          and SPort == dissector.Dissector.preprocess_sessions[i][2]\
           and DPort == dissector.Dissector.preprocess_sessions[i][3]:
            return True
        i = i + 1
    return False


def create_session(Src, Dst, SPort, DPort, expected_seq):
    """
    this method is used for purpose of tcp stream reassemble,
    for creating a new session.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param stream: the initial packet
    @param expected_seq: sequence number
    """
    if not is_created_session(Src, Dst, SPort, DPort):
        dissector.Dissector.preprocess_sessions.append(\
        [Src, Dst, SPort, DPort, expected_seq])


def build_stream(Src, Dst, SPort, DPort, stream):
    """
    this method is used for purpose of tcp stream reassemble,
    for appending a new packet.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param stream: the current packet
    """
    i = 0
    while i < len(dissector.Dissector.preprocess_sessions):
        if  Src == dissector.Dissector.preprocess_sessions[i][0]\
         and Dst == dissector.Dissector.preprocess_sessions[i][1] and\
          SPort == dissector.Dissector.preprocess_sessions[i][2] and\
           DPort == dissector.Dissector.preprocess_sessions[i][3]:
            dissector.Dissector.preprocess_sessions[i][4] =\
             dissector.Dissector.preprocess_sessions[i][4].append_data(\
            Src, Dst, SPort, DPort, stream)
            break
        i = i + 1


def get_stream(Src, Dst, SPort, DPort, obj):
    """
    this method is used for purpose of tcp stream reassemble,
    for retrieving a stream or packet.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param obj: last packet to be appended
    """
    i = 0
    while i < len(dissector.Dissector.sessions):
        if  Src == dissector.Dissector.sessions[i][0] and\
         Dst == dissector.Dissector.sessions[i][1] and\
          SPort == dissector.Dissector.sessions[i][2] and\
           DPort == dissector.Dissector.preprocess_sessions[i][3]:
            if dissector.Dissector.sessions[i][4].seq == obj.seq:
                return dissector.Dissector.sessions[i][4].pkt
        i = i + 1
    return -1


def is_stream_end(Src, Dst, SPort, DPort, obj):
    """
    this method is used for purpose of tcp stream reassemble,
    for checking whether if this is the last packet in the stream or not.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param obj: last packet in stream.
    """
    i = 0
    while i < len(dissector.Dissector.sessions):
        if  Src == dissector.Dissector.sessions[i][0] and\
         Dst == dissector.Dissector.sessions[i][1] and\
          SPort == dissector.Dissector.sessions[i][2] and\
           DPort == dissector.Dissector.sessions[i][3]:
            if dissector.Dissector.sessions[i][4].seq == obj.seq:
                return True
        i = i + 1
    return False


def check_stream(Src, Dst, SPort, DPort, Seq, s):
    """
    this method is used for purpose of tcp stream reassemble,
    for checking whether if this is the last packet in the stream or not.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param seq: sequence number
    @param s: packet payload to create a new session or to be appended in an existed session.
    """
    if not dissector.is_created_session(Src, Dst, SPort, DPort):
        seqn = Seq
        stream = dissector.Stream(s, seqn)
        dissector.create_session(Src, Dst, SPort, DPort, stream)
    elif  dissector.is_created_session(Src, Dst, SPort, DPort):
        seqn = Seq
        stream = dissector.Stream(s, seqn)
        dissector.build_stream(Src, Dst, SPort, DPort, stream)
    if len(dissector.Dissector.sessions) > 0:
        if dissector.is_stream_end(Src, Dst, SPort, DPort, stream):
            s = dissector.get_stream(Src, Dst, SPort, DPort, stream)
            if not s == -1:
                return s
    return -1


class Stream:
    """
    this class is for tcp reassembling
    """
    pkt = ""
    seq = -1
    length_of_last_packet = -1
    stream = False

    def __init__(self, pkt, seq):
        """
        this constructor is used for purpose of tcp stream reassemble,
        for initializing tcp packets.
        @param pkt: packet payload
        @param push: specify if push flag is true or false
        @param seq: sequence number
        """
        self.stream = False
        self.pkt = pkt
        self.seq = seq
        self.length_of_last_packet = len(pkt)

    def append_data(self, Src, Dst, SPort, DPort, obj):
        """
        this method is used for purpose of tcp stream reassemble,
        for appending a packet to an existing stream.
        @param Src: source ip address
        @param Dst: destination ip address
        @param SPort: source port number
        @param DPort: destination port number
        @param obj: last packet in stream.
        """
        if self.seq + self.length_of_last_packet == obj.seq:
            self.stream = True
            self.append_packet(obj.pkt)
            self.change_seq(obj.seq)
            self.length_of_last_packet = len(obj.pkt)
        return self

    def append_packet(self, pkt):
        """
        this method is used for purpose of tcp stream reassemble,
        for appending a packet payload to an existing stream.
        @param pkt: packet payload.
        """
        self.pkt = self.pkt + pkt

    def change_seq(self, seq):
        """
        this method is used for purpose of tcp stream reassemble,
        for the last packet sequence in the stream.
        @param seq: sequence number.
        """
        self.seq = seq


def int2bin(n, count=16):
    """
    this method converts integer numbers to binary numbers
    @param n: the number to be converted
    @param count: the number of binary digits
    """
    return "".join([str((n >> y) & 1) for y in range(count-1, -1, -1)])


class Dissector(Packet):
    """
    this is the main class of this library
    Note:
    implemented protocols like http,sip, (usually or sometimes) return binary
    data, and in some other cases return human readable data,
    so i have decided to make these protocols return the data represented as
    a hex values, you may want to have its payload in ascii too if so then
    use get_ascii()
    """
    packet = None
    type = 0
    preprocess_sessions = []
    sessions = []
    preprocess_done = False
    default_download_folder_changed = False
    path = ""

    def change_dfolder(self, path):
        dissector.Dissector.default_download_folder_changed = True
        if not path[len(path) - 1] == "/" and not path[len(path) - 1] == "\\":
            path = path + "/"
        dissector.Dissector.path = path

    def recalculate_seq(self):
        i = 0
        while i < len(dissector.Dissector.sessions):
            Dissector.sessions[i][4].seq = Dissector.sessions[i][4].seq -\
             Dissector.sessions[i][4].length_of_last_packet
            i = i + 1

    def get_ascii(self, hexstr):
        """
        get hex string and returns ascii chars
        @param hexstr: hex value in str format
        """
        return binascii.unhexlify(hexstr)

    def defined_protocol(self, name):
        if name.startswith("tcp") and name.endswith("tcp") or\
         name.startswith("udp") and name.endswith("udp") or\
          name.startswith("icmp") and name.endswith("icmp") or\
           name.startswith("dns") and name.endswith("dns") or\
            name.startswith("http") and name.endswith("http") or\
             name.startswith("ftp") and name.endswith("ftp") or\
              name.startswith("irc") and name.endswith("irc") or\
               name.startswith("smb") and name.endswith("smb") or\
                name.startswith("sip") and name.endswith("sip") or\
                 name.startswith("telnet") and name.endswith("telnet") or\
                  name.startswith("smtp") or name.startswith("ssh") or\
                   name.startswith("imap") and name.endswith("imap") or\
                    name.startswith("pop") and name.endswith("pop"):
            return True

    def clean_out(self, value):
        value = value.rstrip()
        value = value.lstrip()
        if value.startswith("'") and value.endswith("'"):
            return value[1:-1]
        elif value.startswith("'") and not value.endswith("'"):
            return value[1:]
        elif value.endswith("'") and not value.startswith("'"):
            return value[:-1]
        else:
            return value

    def dissect(self, packet):
        """
        this is the main method in the library, which dissects packets and
        returns them as a list of protocols' fields.
        @param pcapfile: path to a pcap/cap library
        """
        ct = conf.color_theme
        flds = []
        flds.append(ct.layer_name(packet.name))

        for f in packet.fields_desc:
                if isinstance(f, ConditionalField) and not f._evalcond(self):
                    continue
                if isinstance(f, Emph) or f in conf.emph:
                    ncol = ct.emph_field_name
                    vcol = ct.emph_field_value
                else:
                    ncol = ct.field_name
                    vcol = ct.field_value

                fvalue = packet.getfieldval(f.name)
                flds.append((ncol(f.name), vcol(f.i2repr(self, fvalue))))
        return flds

    def is_printable(self, f):
        if isinstance(f, tuple) and not f[1] == "''" and not\
         f[1] == '' and not f[1] == "" and not f[1] == [] and not\
          f[1] == '[]' and not f[1] == "[]" and len(f[1]) > 0:
            return True
        return False

    def __getattr__(self, attr):
        if self.initialized:
            fld, v = self.getfield_and_val(attr)
            if fld is not None:
                return fld.i2h(self, v)
            return v

    def seq_analysis(self, pcapfile):
        """
        this method act as an interface for the dissect() method.
        and to represents the data in the required format.
        @param pcapfile: path to a pcap/cap library
        """
        packetslist = rdpcap(pcapfile)
        pktsfields = []
        protocols = []
        entry = {}
        recognized = False
        for pkt in packetslist:
            firstlayer = True
            if pkt:
                if firstlayer:
                    firstlayer = False
                    self.packet = pkt
                    fields = self.dissect(self.packet)

                load = pkt
                while load.payload:
                    load = load.payload
                    self.packet = load

                    fields = self.dissect(self.packet)

                    if fields[0]:
                        if fields[0] == "NoPayload":
                            break

    def dissect_pkts(self, pcapfile):
        """
        this method act as an interface for the dissect() method.
        and to represents the data in the required format.
        @param pcapfile: path to a pcap/cap library
        """
        self.seq_analysis(pcapfile)
        Dissector.sessions = Dissector.preprocess_sessions
        Dissector.preprocess_sessions = []
        Dissector.preprocess_done = True
        packetslist = rdpcap(pcapfile)
        pktsfields = []
        protocols = []
        entry = {}
        recognized = False
        for pkt in packetslist:
            firstlayer = True
            if pkt:
                if firstlayer:
                    firstlayer = False
                    self.packet = pkt
                    fields = self.dissect(self.packet)

                    j = 1
                    entry = {}
                    while j < len(fields):
                        if self.is_printable(fields[j]):
                            entry[fields[j][0]] = fields[j][1]
                        j = j + 1

                    i = 0
                    while i < len(protocols):
                        if fields[0] in protocols[i]:
                            protocols[i].append(entry)
                            break
                        elif fields[0] not in protocols[i] and \
                        i == len(protocols) - 1:
                            protocols.append([fields[0]])
                            protocols[i + 1].append(entry)
                            break
                        i = i + 1
                    if len(protocols) == 0:
                        protocols.append([fields[0]])
                        protocols[0].append(entry)

                load = pkt
                while load.payload:
                    load = load.payload
                    self.packet = load

                    fields = self.dissect(self.packet)

                    entry = {}
                    if fields[0]:
                        if fields[0] == "NoPayload":
                            break

                    j = 1
                    first = True
                    if not recognized:
                        entry = {}
                    while j < len(fields):
                        if self.is_printable(fields[j]):
                            if fields[0] == "UDP":
                                recognized = True
                                entry["src"] = load.underlayer.fields["src"]
                                entry["dst"] = load.underlayer.fields["dst"]
                                entry["sdport"] = load.fields["sport"]
                                entry["dport"] = load.fields["dport"]
                            if fields[0] == "TCP":
                                recognized = True
                                entry["src"] = load.underlayer.fields["src"]
                                entry["dst"] = load.underlayer.fields["dst"]
                                entry["sdport"] = load.fields["sport"]
                                entry["dport"] = load.fields["dport"]

                            if fields[0] == "DNS":
                                recognized = True
                                qdfield = None
                                anfield = None
                                type = None
                                name = None
                                pname = None
                                found = False
                                entry = []
                                if load.fields["qd"]:
                                    for element in fields:
                                        if "qd" in element:
                                            qdfield = element[1]
                                    if qdfield.count("|") == 1:
                                        line = qdfield.split()
                                        for t in line:
                                            if t.startswith("qname="):
                                                found = True
                                                name = t[6:]
                                            if t.startswith("qtype="):
                                                found = True
                                                type = t[6:]
                                        if found:
                                            entry.append(\
                                            {"name": name, "type": type})
                                            found = False

                                    if qdfield.count("|") > 1:
                                        entry["name"] = []
                                        qlist = qdfield.split(" |")
                                        for record in qlist:
                                            line = record.split()
                                            for t in line:
                                                if t.startswith("qname="):
                                                    found = True
                                                    name = t[6:]
                                                if t.startswith("qtype="):
                                                    found = True
                                                    type = t[6:]
                                            if found:
                                                entry.append(\
                                                {"name": name, "type": type})
                                                found = False

                                if load.fields["an"]:
                                    for element in fields:
                                        if "an" in element:
                                            anfield = element[1]

                                    if anfield.count("|") == 1:
                                        line = anfield.split()
                                        for t in line:
                                            if t.startswith("rrname="):
                                                found = True
                                                name = t[7:]
                                            if t.startswith("type="):
                                                found = True
                                                type = t[5:]
                                            if t.startswith("rdata="):
                                                found = True
                                                pname = t[6:]
                                        if found:
                                            entry.append(\
                                {"name": name, "type": type, "pname": pname})
                                            found = False
                                    if anfield.count("|") > 1:
                                        alist = anfield.split(" |")
                                        for record in alist:
                                            line = record.split()
                                            for t in line:
                                                if t.startswith("rrname="):
                                                    found = True
                                                    name = t[7:]
                                                if t.startswith("type="):
                                                    found = True
                                                    type = t[5:]
                                                if t.startswith("rdata="):
                                                    found = True
                                                    pname = t[6:]
                                            if found:
                                                entry.append(\
                    {"name": name[1:-2], "type": type, "pname": pname[1:-1]})
                                                found = False

                            if isinstance(fields[0], str) and\
                             fields[0].startswith("http"):
                                recognized = True
                                if isinstance(fields[j][1], str):
                                    if first and not fields[j][0][:-2] ==\
                                     "unknown-header(s)" and\
                                      not fields[j][0][:-2] == "message-body":
                                        entry[fields[j][0][:-2]] =\
                         self.clean_out(fields[j][1][len(fields[j][0]) + 1:-1])
                                    elif first and fields[j][0][:-2] ==\
                                     "unknown-header(s)":
                                        entry[fields[j][0][:-2]] =\
                                         self.clean_out(fields[j][1])
                                    elif first and fields[j][0][:-2] ==\
                                     "message-body":
                                        entry[fields[j][0][:-2]] = fields[j][1]
                                    else:
                                        entry[fields[j][0]] =\
                                         self.clean_out(fields[j][1])

                            if isinstance(fields[0], str) and\
                            fields[0].startswith("sip"):
                                recognized = True
                                if isinstance(fields[j][1], str):
                                    if first and not fields[j][0][:-2] ==\
                                     "unknown-header(s)" and not\
                                      fields[j][0][:-2] == "message-body":
                                        entry[fields[j][0][:-2]] =\
                        self.clean_out(fields[j][1][len(fields[j][0]) + 1:-1])
                                    elif first and fields[j][0][:-2] ==\
                                     "unknown-header(s)":
                                        entry[fields[j][0][:-2]] =\
                                         self.clean_out(fields[j][1])
                                    elif first and fields[j][0][:-2] ==\
                                     "message-body":
                                        entry[fields[j][0][:-2]] =\
                                         fields[j][1][1:-1]
                                else:
                                    entry[fields[j][0]] = self.clean_out(\
                                    self.clean_out(fields[j][1]))

                            if isinstance(fields[0], str) and\
                            fields[0].startswith("smtp"):
                                recognized = True
                                if fields[j][0].startswith("command") and\
                                 fields[j][1].startswith("['DATA', '") and\
                                  fields[j][1].endswith("']"):

                                    entry["data"] = fields[j][1][10:-2]
                                    entry["type"] = "data"
                                elif fields[j][0].startswith("response") and\
                                 fields[j][0].endswith("response"):
                                    result = fields[j][1]
                                    result = "[" +\
                                     result[1:-1].replace("'", '"') + "]"
                                    try:
                                        result = json.loads(result)
                                    except Exception:
                                        None
                                    entry[fields[j][0]] = result
                                    entry["type"] = "response"
                                elif fields[j][0].startswith("command") or\
                                 fields[j][0].startswith("argument"):
                                    if isinstance(entry, dict):
                                        entry[fields[j][0]] =\
                                         fields[j][1][1:-1]
                                        if not "type" in entry:
                                            entry["type"] = "request"
                                        if j == len(fields) - 1:
                                            temp = ""
                                            if entry["type"] == "request":
                                                if "command" in entry:
                                                    temp = "command: " +\
                                                     entry["command"]
                                                    if entry["command"] ==\
                                                     "DATA":
                                                        None
                                                if "argument" in entry:
                                                    temp = temp +\
                                         ", argument: " + entry["argument"]
                                                if "type" in entry:
                                                    temp = temp +\
                                                     ", type: " + entry["type"]
                                                entry = temp
                                    elif isinstance(entry, str):
                                        if len(entry) > 0:
                                            entry = entry + ", " +\
                                     fields[j][0] + ": " + fields[j][1][1:-1]
                                        else:
                                            entry = fields[j][0] + ": " +\
                                             fields[j][1][1:-1]
                                        if j == len(fields) - 1:
                                            entry = entry + ", type: request"
                                        else:
                                            entry = entry + fields[j][0] +\
                                             ": " + fields[j][1][1:-1]
                                        if j == len(fields) - 1:
                                            entry = entry + ", type: request"

                            if isinstance(fields[0], str) and\
                            fields[0].startswith("ftp"):
                                recognized = True
                                if isinstance(entry, dict):
                                    entry = ""
                                if len(entry) > 0:
                                    entry = entry + ", " +\
             fields[j][0] + ": " + self.clean_out(fields[j][1][1:-1])
                                else:
                                    entry = entry + fields[j][0] +\
                                     ": " + self.clean_out(fields[j][1][1:-1])
                                if j == len(fields) - 1 and\
                                 pkt.payload.payload.fields["sport"] == 21 or\
                                  pkt.payload.payload.fields["sport"] == 20:
                                    entry = entry + ", type: response"
                                elif j == len(fields) - 1 and\
                                 pkt.payload.payload.fields["dport"] == 21 or\
                                  pkt.payload.payload.fields["dport"] == 20:
                                    entry = entry + ", type: request"
                            if isinstance(fields[0], str) and\
                            fields[0].startswith("imap"):
                                recognized = True
                                entry = entry + fields[j][1] + " "
                            if isinstance(fields[0], str) and\
                             fields[0].startswith("pop"):
                                recognized = True
                                entry = entry + fields[j][1] + " "
                            if isinstance(fields[0], str) and\
                             fields[0].startswith("irc"):
                                recognized = True
                                entry = fields[j][1][1:-1]

                            if isinstance(fields[0], str) and\
                             fields[0].startswith("telnet"):
                                recognized = True
                                entry = fields[j][1][:-1]

                            if isinstance(fields[0], str) and\
                             fields[0].startswith("ssh"):
                                recognized = True
                                entry = fields[j][1]
                                if j == len(fields) - 1 and\
                                 pkt.payload.payload.fields["sport"] == 22:
                                    entry = entry + ", type: response"
                                elif j == len(fields) - 1 and\
                                 pkt.payload.payload.fields["dport"] == 22:
                                    entry = entry + ", type: request"

                            if not recognized:
                                entry[fields[j][0]] =\
                                 self.clean_out(fields[j][1])
                            recognized = False
                        j = j + 1

                    i = 0
                    while i < len(protocols):
                        if fields[0].lower() in protocols[i]:
                            if len(entry) > 0:
                                protocols[i].append(entry)
                            break
                        elif fields[0].lower() not in protocols[i] and \
                        i == len(protocols) - 1:
                            protocols.append([fields[0].lower()])
                            if len(entry) > 0:
                                protocols[i + 1].append(entry)
                            break
                        i = i + 1
                    if len(protocols) == 0:
                        protocols.append([fields[0].lower()])
                        if len(entry) > 0:
                            protocols[0].append(entry)

        dproto = {}
        i = 0
        for proto in protocols:
            if self.defined_protocol(proto[0].lower()):

                dproto[proto[0].lower()] = proto[1:]

        return dproto
