import binascii
import base64
import json
from scapy.packet import *
from scapy.utils import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
import dissector

preprocess_sessions = []
sessions = []


def is_created_stream_session(Src, Dst, SPort, DPort):
    """
    this method is used for purpose of tcp stream reassemble,
    for checking if this is a new session of not.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    """
    i = 0
    while i < len(preprocess_sessions):
        if  Src == preprocess_sessions[i][0] and\
         Dst == preprocess_sessions[i][1] and\
          SPort == preprocess_sessions[i][2] and\
           DPort == preprocess_sessions[i][3]:
            return True
        i = i + 1
    return False


def create_stream_session(Src, Dst, SPort, DPort, stream):
    """
    this method is used for purpose of tcp stream reassemble,
    for creating a new session.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param stream: the initial packet
    """
    if stream.push:
        sessions.append([Src, Dst, SPort, DPort, stream])
    else:
        preprocess_sessions.append([Src, Dst, SPort, DPort, stream])


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
    while i < len(preprocess_sessions):
        if  Src == preprocess_sessions[i][0] and\
         Dst == preprocess_sessions[i][1] and\
          SPort == preprocess_sessions[i][2] and\
           DPort == preprocess_sessions[i][3]:
            if not stream.push:
                preprocess_sessions[i][4] =\
             preprocess_sessions[i][4].append_data(\
                Src, Dst, SPort, DPort, stream)
            else:
                sessions.append(\
    [Src, Dst, SPort, DPort, preprocess_sessions[i][4].append_data(\
                Src, Dst, SPort, DPort, stream)])
                del(preprocess_sessions[i])
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
    while i < len(sessions):
        if Src == sessions[i][0] and Dst == sessions[i][1] and\
         SPort == sessions[i][2] and DPort == sessions[i][3]:
            if sessions[i][4].seq == obj.seq:
                return sessions[i][4].pkt
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
    while i < len(sessions):
        if  Src == sessions[i][0] and Dst == sessions[i][1] and\
         SPort == sessions[i][2] and DPort == sessions[i][3]:
            if sessions[i][4].seq == obj.seq:
                return True
        i = i + 1
    return False


class Stream:
    """
    this class is for tcp reassembling
    """
    pkt = ""
    seq = -1
    push = None
    length_of_last_packet = -1
    stream = False

    def __init__(self, pkt, push, seq):
        """
        this constructor is used for purpose of tcp stream reassemble,
        for initializing tcp packets.
        @param pkt: packet payload
        @param push: specify if push flag is true or false
        @param seq: sequence number
        """
        self.stream = False
        self.pkt = pkt
        self.push = push
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
        if self.seq + self.length_of_last_packet == obj.seq and obj.push:
            self.stream = True
            self.append_packet(obj.pkt)
            self.change_seq(obj.seq)
            self.push = obj.push
            self.length_of_last_packet = len(obj.pkt)
        elif self.seq + self.length_of_last_packet == obj.seq:
            self.append_packet(obj.pkt)
            self.change_seq(obj.seq)
            self.push = obj.push
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

# holds ssh encrypted sessions
encryptedsessions = []


def is_created_session(Src, Dst, SPort, DPort):
    """
    method returns true if the ssh session is exist
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    """
    i = 0
    while i < len(encryptedsessions):
        if  Src and Dst and SPort and DPort in encryptedsessions[i]:
            return True
        i = i + 1
    return False


def create_session(Src, Dst, SPort, DPort, Macl):
    """
    method for creating encypted ssh sessions
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    """
    if not is_created_session(Src, Dst, SPort, DPort):
        encryptedsessions.append([Src, Dst, SPort, DPort, Macl, False])


def set_as_encrypted(Src, Dst, SPort, DPort):
    """
    set the ssh session as encrypted
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    """
    i = 0
    while i < len(encryptedsessions):
        if  Src and Dst and SPort and DPort in encryptedsessions[i]:
            encryptedsessions[i] = [Src, Dst, SPort, DPort,\
                                     encryptedsessions[i][4], True]
        i = i + 1
    return -1


def is_encrypted_session(Src, Dst, SPort, DPort):
    """
    returns true if the ssh session is encrypted
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    """
    i = 0
    while i < len(encryptedsessions):
        if  Src and Dst and SPort and DPort and True in encryptedsessions[i]:
            return True
        i = i + 1
    return False


def get_mac_length(Src, Dst, SPort, DPort):
    """
    method for maintaining the length of the mac for specific ssh session
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    """
    i = 0
    while i < len(encryptedsessions):
        if  Src and Dst and SPort and DPort in encryptedsessions[i]:
            return encryptedsessions[i][4]
        i = i + 1
    return -1


class SSHField(XByteField):
    """
    this is a field class for handling the ssh packets
    @attention: this class inherets XByteField
    """
    found = False
    encryptionstarted = False
    macstarted = False
    maclength = 0
    holds_packets = 1
    name = "SSHField"
    myresult = ""

    def get_ascii(self, hexstr):
        """
        get hex string and returns ascii chars
        @param hexstr: hex value in str format
        """
        return binascii.unhexlify(hexstr)

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

    def get_discnct_msg(self, cn):
        """
        method returns a message for every a specific code number
        @param cn: code number
        """
        codes = {
                 1: "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT",
                 2: "SSH_DISCONNECT_PROTOCOL_ERROR",
                 3: "SSH_DISCONNECT_KEY_EXCHANGE_FAILED",
                 4: "SSH_DISCONNECT_RESERVED",
                 5: "SSH_DISCONNECT_MAC_ERROR",
                 6: "SSH_DISCONNECT_COMPRESSION_ERROR",
                 7: "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE",
                 8: "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED",
                 9: "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE",
                 10: "SSH_DISCONNECT_CONNECTION_LOST",
                 11: "SSH_DISCONNECT_BY_APPLICATION",
                 12: "SSH_DISCONNECT_TOO_MANY_CONNECTIONS",
                 13: "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER",
                 14: "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE",
                 15: "SSH_DISCONNECT_ILLEGAL_USER_NAME",
                 }
        if cn in codes:
            return codes[cn] + " "
        return "UnknownCode[" + str(cn) + "] "

    def get_code_msg(self, cn):
        """
        method returns a message for every a specific code number
        @param cn: code number
        """
        codes = {
                 1: "SSH_MSG_DISCONNECT",
                 2: "SSH_MSG_IGNORE",
                 3: "SSH_MSG_UNIMPLEMENTED",
                 4: "SSH_MSG_DEBUG",
                 5: "SSH_MSG_SERVICE_REQUEST",
                 6: "SSH_MSG_SERVICE_ACCEPT",
                 20: "SSH_MSG_KEXINIT",
                 21: "SSH_MSG_NEWKEYS",
                 30: "SSH_MSG_KEXDH_INIT",
                 31: "SSH_MSG_KEXDH_REPLY",
                 32: "SSH_MSG_KEX_DH_GEX_INIT",
                 33: "SSH_MSG_KEX_DH_GEX_REPLY",
                 34: "SSH_MSG_KEX_DH_GEX_REQUEST",
                 50: "SSH_MSG_USERAUTH_REQUEST",
                 51: "SSH_MSG_USERAUTH_FAILURE",
                 52: "SSH_MSG_USERAUTH_SUCCESS",
                 53: "SSH_MSG_USERAUTH_BANNER",
                 60: "SSH_MSG_USERAUTH_PK_OK",
                 80: "SSH_MSG_GLOBAL_REQUEST",
                 81: "SSH_MSG_REQUEST_SUCCESS",
                 82: "SSH_MSG_REQUEST_FAILURE",
                 90: "SSH_MSG_CHANNEL_OPEN",
                 91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
                 92: "SSH_MSG_CHANNEL_OPEN_FAILURE",
                 93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",
                 94: "SSH_MSG_CHANNEL_DATA",
                 95: "SSH_MSG_CHANNEL_EXTENDED_DATA",
                 96: "SSH_MSG_CHANNEL_EOF",
                 97: "SSH_MSG_CHANNEL_CLOSE",
                 98: "SSH_MSG_CHANNEL_REQUEST",
                 99: "SSH_MSG_CHANNEL_SUCCESS",
                 100: "SSH_MSG_CHANNEL_FAILURE"}
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
        ss = -1
        flags = None
        seq = pkt.underlayer.fields["seq"]
        push = False
        flags_bits = list(int2bin(pkt.underlayer.fields["flags"]))
        if flags_bits[11] == '1':
            flags = 'A'
        if flags_bits[12] == '1':
            flags = flags + 'P'
        if 'P' in flags:
            push = True
        else:
            push = False

        if not is_created_stream_session(\
        pkt.underlayer.underlayer.fields["src"],\
         pkt.underlayer.underlayer.fields["dst"],\
          pkt.underlayer.fields["sport"], pkt.underlayer.fields["dport"]):
            seqn = pkt.underlayer.fields["seq"]
            stream = Stream(s, push, seqn)
            create_stream_session(\
            pkt.underlayer.underlayer.fields["src"],\
             pkt.underlayer.underlayer.fields["dst"],\
              pkt.underlayer.fields["sport"],\
               pkt.underlayer.fields["dport"], stream)
        elif is_created_stream_session(\
            pkt.underlayer.underlayer.fields["src"],\
             pkt.underlayer.underlayer.fields["dst"],\
              pkt.underlayer.fields["sport"],\
               pkt.underlayer.fields["dport"]):
            seqn = pkt.underlayer.fields["seq"]
            stream = Stream(s, push, seqn)
            build_stream(\
            pkt.underlayer.underlayer.fields["src"],\
             pkt.underlayer.underlayer.fields["dst"],\
              pkt.underlayer.fields["sport"],\
               pkt.underlayer.fields["dport"], stream)

        if not dissector.Dissector.preprocess_done:
            return "", ""
        if len(sessions) > 0:
            if is_stream_end(\
            pkt.underlayer.underlayer.fields["src"],\
             pkt.underlayer.underlayer.fields["dst"],\
              pkt.underlayer.fields["sport"],\
               pkt.underlayer.fields["dport"], stream):
                ss = get_stream(\
                pkt.underlayer.underlayer.fields["src"],\
                 pkt.underlayer.underlayer.fields["dst"],\
                  pkt.underlayer.fields["sport"],\
                   pkt.underlayer.fields["dport"], stream)
            if not ss == -1:
                s = ss
            else:
                return "", ""
        self.myresult = ""
        resultlist = []
        if s.upper().startswith("SSH"):
            return "", s
        for c in s:
            ustruct = struct.unpack(self.fmt, c)
            byte = str(hex(ustruct[0]))[2:]
            if len(byte) == 1:
                byte = "0" + byte
            self.myresult = self.myresult + byte

        if not s.startswith("SSH") and len(self.myresult) > 12:
            if not is_encrypted_session(\
            pkt.underlayer.underlayer.fields["src"],\
            pkt.underlayer.underlayer.fields["dst"],\
            pkt.underlayer.fields["sport"],\
            pkt.underlayer.fields["dport"]):
                pakl = str(int(self.myresult[:8], 16))
                padl = str(int(self.myresult[8:10], 16))
                payloadl = int(pakl) - int(padl) - 1
                opcode = self.get_code_msg(int(self.myresult[10:12], 16))
                payload = self.myresult[12:12 + payloadl * 2]
                padding = self.myresult[12 + payloadl * 2:12 + payloadl * 2\
                                         + int(padl) * 2]
                resultlist.append(("packet_length", pakl))
                resultlist.append(("padding_length", padl))
                resultlist.append(("opcode", opcode))

            if is_encrypted_session(pkt.underlayer.underlayer.fields["src"],
                                  pkt.underlayer.underlayer.fields["dst"],
                                  pkt.underlayer.fields["sport"],
                                  pkt.underlayer.fields["dport"]):
                if is_created_session(pkt.underlayer.underlayer.fields["src"],
                                    pkt.underlayer.underlayer.fields["dst"],
                                    pkt.underlayer.fields["sport"],
                                    pkt.underlayer.fields["dport"]):
                    encrypted_payload = base64.standard_b64encode(\
                            self.get_ascii(self.myresult[:\
                    get_mac_length(pkt.underlayer.underlayer.fields["src"],
                                 pkt.underlayer.underlayer.fields["dst"],
                                 pkt.underlayer.fields["sport"],
                                 pkt.underlayer.fields["dport"]) * 2]))
                else:
                    encrypted_payload = base64.standard_b64encode(\
                                        self.myresult[:])

                resultlist.append(("encrypted_payload", encrypted_payload))

                if is_created_session(pkt.underlayer.underlayer.fields["src"],
                                    pkt.underlayer.underlayer.fields["dst"],
                                    pkt.underlayer.fields["sport"],
                                    pkt.underlayer.fields["dport"]):
                    mac = base64.standard_b64encode(\
                    self.get_ascii(self.myresult[\
                    get_mac_length(pkt.underlayer.underlayer.fields["src"],\
                                    pkt.underlayer.underlayer.fields["dst"],\
                                    pkt.underlayer.fields["sport"],\
                                    pkt.underlayer.fields["dport"]) * 2:]))
                    resultlist.append(("mac", mac))

            if not is_encrypted_session(\
                                    pkt.underlayer.underlayer.fields["src"],\
                                      pkt.underlayer.underlayer.fields["dst"],\
                                      pkt.underlayer.fields["sport"],\
                                      pkt.underlayer.fields["dport"]) and\
                                       opcode.startswith("SSH_MSG_KEXDH_INIT"):
                try:
                    e_length = int(self.myresult[12:20], 16)
                    e = base64.standard_b64encode(\
                        self.get_ascii(self.myresult[20:20 + e_length * 2]))
                    resultlist.append(("e_length", str(e_length)))
                    resultlist.append(("e", e))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],\
                pkt.underlayer.fields["dport"]) and\
                                  opcode.startswith("SSH_MSG_KEXDH_REPLY"):
                try:
                    server_public_host_key_and_certificates_K_S_length =\
                     int(self.myresult[12:20], 16)
                    server_public_host_key_and_certificates_K_S =\
                     self.myresult[20:20 +\
                     server_public_host_key_and_certificates_K_S_length * 2]
                    f_length = int(self.myresult[20 + \
                        server_public_host_key_and_certificates_K_S_length\
                 * 2:20 + server_public_host_key_and_certificates_K_S_length\
                                 * 2 + 8], 16)
                    f = base64.standard_b64encode(\
                        self.get_ascii(self.myresult[20 +\
                    server_public_host_key_and_certificates_K_S_length\
        * 2 + 8:20 + server_public_host_key_and_certificates_K_S_length\
                     * 2 + 8 + f_length * 2]))
                    signature_of_h_length = int(self.myresult[20 +\
                     server_public_host_key_and_certificates_K_S_length\
                      * 2 + 8 + f_length * 2:20 +\
                       server_public_host_key_and_certificates_K_S_length\
                        * 2 + 8 + f_length * 2 + 8], 16)
                    signature_of_h = self.myresult[20 +\
                     server_public_host_key_and_certificates_K_S_length\
                      * 2 + 8 + f_length * 2 + 8:20 +\
                       server_public_host_key_and_certificates_K_S_length\
                        * 2 + 8 + f_length * 2 + 8 +\
                         signature_of_h_length * 2]
                    resultlist.append(\
            ("server_public_host_key_and_certificates_K_S_length",\
                     str(server_public_host_key_and_certificates_K_S_length)))
                    resultlist.append(\
                    ("server_public_host_key_and_certificates_K_S",\
            base64.standard_b64encode(\
                self.get_ascii(server_public_host_key_and_certificates_K_S))))
                    resultlist.append(("f_length", str(f_length)))
                    resultlist.append(("f", f))
                    resultlist.append(("signature_of_h_length",
                     str(signature_of_h_length)))
                    resultlist.append(("signature_of_h",
                     base64.standard_b64encode(\
                    self.get_ascii(signature_of_h))))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],\
                pkt.underlayer.fields["dport"])\
                and opcode.startswith("SSH_MSG_SERVICE_REQUEST"):
                try:
                    service_name_length = int(self.myresult[12:20], 16)
                    service_name = self.myresult[20:20 \
                    + service_name_length * 2]
                    resultlist.append(("service_name_length",
                     str(service_name_length)))
                    resultlist.append(("service_name",
                     base64.standard_b64encode(self.get_ascii(service_name))))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],\
                pkt.underlayer.fields["dport"])\
                and opcode.startswith("SSH_MSG_SERVICE_ACCEPT"):
                try:
                    service_name_length = int(self.myresult[12:20], 16)
                    service_name = self.myresult[20:20 +\
                                                  service_name_length * 2]
                    resultlist.append(("service_name_length",
                                        str(service_name_length)))
                    resultlist.append(("service_name",
                                        self.get_ascii(service_name)))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],\
                pkt.underlayer.fields["dport"])\
                and opcode.startswith("SSH_MSG_NEWKEYS"):
                try:
                    set_as_encrypted(pkt.underlayer.underlayer.fields["src"],
                                   pkt.underlayer.underlayer.fields["dst"],
                                   pkt.underlayer.fields["sport"],
                                   pkt.underlayer.fields["dport"])
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                    pkt.underlayer.underlayer.fields["src"],\
                    pkt.underlayer.underlayer.fields["dst"],\
                    pkt.underlayer.fields["sport"],\
                    pkt.underlayer.fields["dport"])\
                    and opcode.startswith("SSH_MSG_DISCONNECT"):
                try:
                    reason_code = self.get_discnct_msg(int(\
                    self.myresult[12:20], 16)) * 2
                    description_length = int(\
                    self.myresult[20:28], 16)
                    description = self.myresult[28:28 +\
                     description_length * 2]
                    language_tag_length = int(\
                    self.myresult[28 + description_length * 2:28 +\
                     description_length * 2 + 8], 16)
                    language_tag = self.myresult[28 + description_length\
                     * 2 + 8:28 + description_length * 2 + 8 +\
                      language_tag_length * 2]
                    resultlist.append(("reason_code", reason_code))
                    resultlist.append(("description_length",
                                        str(description_length)))
                    resultlist.append(("description",
                                        self.get_ascii(description)))
                    resultlist.append(("language_tag_length",
                                        str(language_tag_length)))
                    resultlist.append(("language_tag",
                                        self.get_ascii(language_tag)))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],\
                pkt.underlayer.fields["dport"])\
                and opcode.startswith("SSH_MSG_IGNORE"):
                try:
                    data_length = int(self.myresult[12:20], 16)
                    data = self.myresult[20:20 + data_length * 2]
                    resultlist.append(("data_length", str(data_length)))
                    resultlist.append(\
                    ("data", base64.standard_b64encode(self.get_ascii(data))))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
            pkt.underlayer.underlayer.fields["src"],\
            pkt.underlayer.underlayer.fields["dst"],\
            pkt.underlayer.fields["sport"],\
            pkt.underlayer.fields["dport"])\
            and opcode.startswith("SSH_MSG_USERAUTH_PK_OK"):
                try:
                    public_key_algorithm_name_from_the_request_length =\
                     int(self.myresult[12:20], 16)
                    public_key_algorithm_name_from_the_request =\
                     self.myresult[20:20 +\
                     public_key_algorithm_name_from_the_request_length * 2]
                    public_key_blob_from_the_request_length = int(\
                    self.myresult[20 + \
                    public_key_algorithm_name_from_the_request_length * 2:20\
                     + public_key_algorithm_name_from_the_request_length * 2\
                      + 8], 16)
                    public_key_blob_from_the_request = self.myresult[20 +\
                     public_key_algorithm_name_from_the_request_length * 2 +\
                 8:20 + public_key_algorithm_name_from_the_request_length\
                       * 2 + 8 + public_key_blob_from_the_request_length * 2]
                    resultlist.append((\
                    "public_key_algorithm_name_from_the_request_length",
                     str(public_key_algorithm_name_from_the_request_length)))
                    resultlist.append(\
                    ("public_key_algorithm_name_from_the_request",\
                     self.get_ascii(\
                    public_key_algorithm_name_from_the_request)))
                    resultlist.append(\
                    ("public_key_blob_from_the_request_length",
                     str(public_key_blob_from_the_request_length)))
                    resultlist.append(("public_key_blob_from_the_request",
                     self.get_ascii(public_key_blob_from_the_request)))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
            pkt.underlayer.underlayer.fields["src"],\
            pkt.underlayer.underlayer.fields["dst"],\
            pkt.underlayer.fields["sport"],\
            pkt.underlayer.fields["dport"])\
            and opcode.startswith("SSH_MSG_DEBUG"):
                try:
                    always_display_boolean = int(self.myresult[12:14], 16)
                    description_length = int(self.myresult[14:22], 16)
                    description = self.myresult[22:22 +\
                     description_length * 2]
                    language_tag_length = int(self.myresult[22 +\
                     description_length * 2:22 + description_length\
                      * 2 + 8], 16)
                    language_tag = self.myresult[22 + description_length\
                     * 2 + 8:22 + description_length * 2 + 8 +\
                      language_tag_length * 2]
                    resultlist.append(("always_display_boolean",
                                        always_display_boolean))
                    resultlist.append(("description_length",
                                        str(description_length)))
                    resultlist.append(("description",
                                        self.get_ascii(description)))
                    resultlist.append(("language_tag_length",
                                        str(language_tag_length)))
                    resultlist.append(("language_tag",
                                        self.get_ascii(language_tag)))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],
                pkt.underlayer.fields["dport"])\
                and opcode.startswith("SSH_MSG_UNIMPLEMENTED"):
                try:
                    seqn = int(self.myresult[12:20], 16)
                    resultlist.append(\
                    ("packet sequence number of rejected message", seqn))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],\
                pkt.underlayer.fields["dport"])\
                and opcode.startswith("SSH_MSG_CHANNEL_DATA"):
                try:
                    recipient_channel = int(self.myresult[12:20], 16)
                    data_length = int(self.myresult[20:28], 16)
                    data = self.myresult[28:28 + data_length * 2]
                    resultlist.append(("recipient_channel", recipient_channel))
                    resultlist.append(("data_length", str(data_length)))
                    resultlist.append(\
                    ("data", base64.standard_b64encode(self.get_ascii(data))))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
                pkt.underlayer.underlayer.fields["dst"],\
                pkt.underlayer.fields["sport"],\
                pkt.underlayer.fields["dport"])\
                and opcode.startswith("SSH_MSG_USERAUTH_REQUEST"):
                try:
                    user_name_length = int(self.myresult[12:20], 16)
                    user_name = self.myresult[20:20 + user_name_length * 2]
                    service_name_length = int(self.myresult[20 +\
                     user_name_length * 2:20 + user_name_length * 2 + 8], 16)
                    service_name = self.myresult[20 + user_name_length *\
                     2 + 8:20 + user_name_length * 2 + 8 +\
                      service_name_length * 2]
                    method_name_length = int(self.myresult[20 +\
                     user_name_length * 2 + 8 + service_name_length *\
                      2:20 + user_name_length * 2 + 8 + service_name_length\
                       * 2 + 8], 16)
                    method_name = self.myresult[20 + user_name_length *\
                     2 + 8 + service_name_length * 2 + 8:20 +\
                      user_name_length * 2 + 8 + service_name_length *\
                       2 + 8 + method_name_length * 2]
                    resultlist.append(("user_name_length",
                                        str(user_name_length)))
                    resultlist.append(("user_name",
                                        self.get_ascii(user_name)))
                    resultlist.append(("service_name_length",
                                        str(service_name_length)))
                    resultlist.append(("service_name",
                                        self.get_ascii(service_name)))
                    resultlist.append(("method_name_length",
                                        str(method_name_length)))
                    resultlist.append(("method_name",
                                        self.get_ascii(method_name)))

                    if method_name.startswith("publickey"):
                        boolean = int(self.myresult[20 + user_name_length *\
                         2 + 8 + service_name_length * 2 + 8 +\
                          method_name_length * 2:20 + user_name_length *\
                           2 + 8 + service_name_length * 2 + 8 +\
                            method_name_length * 2 + 8], 16)
                        public_key_algorithm_name_length =\
                         int(self.myresult[20 + user_name_length * 2 + 8 +\
                         service_name_length * 2 + 8 + method_name_length\
                          * 2 + 8:20 + user_name_length * 2 + 8 +\
                           service_name_length * 2 + 8 + method_name_length\
                            * 2 + 8 + 8], 16)
                        public_key_algorithm_name = self.myresult[20 +\
                         user_name_length * 2 + 8 + service_name_length *\
                          2 + 8 + method_name_length * 2 + 8 + 8:20 +\
                           user_name_length * 2 + 8 + service_name_length *\
                            2 + 8 + method_name_length * 2 + 8 + 8 +\
                             public_key_algorithm_name_length * 2]
                        resultlist.append(("boolean", boolean))
                        resultlist.append(("public_key_algorithm_name_length",
                        str(public_key_algorithm_name_length)))
                        resultlist.append(("public_key_algorithm_name",
                        self.get_ascii(public_key_algorithm_name)))
                        if boolean == 0:
                            public_key_blob_length =\
                             int(self.myresult[20 + user_name_length * 2 +\
                             8 + service_name_length * 2 + 8 +\
                              method_name_length * 2 + 8 + 8 +\
                               public_key_algorithm_name_length * 2:20 +\
                                user_name_length * 2 + 8 +\
                                 service_name_length * 2 + 8 +\
                                  method_name_length * 2 + 8 + 8 +\
                                   public_key_algorithm_name_length * 2 + 8],
                                  16)
                            public_key_blob = self.myresult[20 +\
                             user_name_length * 2 + 8 + service_name_length *\
                              2 + 8 + method_name_length * 2 + 8 + 8 +\
                               public_key_algorithm_name_length * 2 + 8:20 +\
                                user_name_length * 2 + 8 +\
                                 service_name_length * 2 + 8 +\
                                  method_name_length * 2 + 8 + 8 +\
                                   public_key_algorithm_name_length * 2 + 8 +\
                                    public_key_blob_length * 2]
                            resultlist.append(("public_key_blob_length",
                                                str(public_key_blob_length)))
                            resultlist.append(("public_key_blob",
                                                self.get_ascii(\
                                                public_key_blob)))
                        if boolean != 0:
                            public_key_to_be_used_for_authentication_length =\
                             int(self.myresult[20 + user_name_length * 2 +\
                             8 + service_name_length * 2 + 8 +\
                              method_name_length * 2 + 8 + 8 +\
                               public_key_algorithm_name_length * 2:20 +\
                                user_name_length * 2 + 8 +\
                                 service_name_length * 2 + 8 +\
                                  method_name_length * 2 + 8 + 8 +\
                                   public_key_algorithm_name_length * 2 + 8],\
                                  16)
                            public_key_to_be_used_for_authentication =\
                             self.myresult[20 + user_name_length * 2 + 8 +\
                             service_name_length * 2 + 8 + method_name_length\
                              * 2 + 8 + 8 + public_key_algorithm_name_length\
                               * 2 + 8:20 + user_name_length * 2 + 8 +\
                                service_name_length * 2 + 8 +\
                                 method_name_length * 2 + 8 + 8 +\
                                  public_key_algorithm_name_length * 2 + 8 +\
                                   public_key_blob_length * 2]
                            signature_length = \
                            int(self.myresult[20 + user_name_length * 2 + 8 +\
                             service_name_length * 2 + 8 +\
                              method_name_length * 2 + 8 + 8 +\
                               public_key_algorithm_name_length * 2 + 8 +\
                            public_key_to_be_used_for_authentication_length\
                             * 2:20 + user_name_length * 2 + 8 +\
                              service_name_length * 2 + 8 +\
                               method_name_length * 2 + 8 + 8 +\
                                public_key_algorithm_name_length * 2 + 8 +\
                             public_key_to_be_used_for_authentication_length\
                                  * 2 + 8], 16)
                            signature = self.myresult[20 + user_name_length *\
                            2 + 8 + service_name_length * 2 + 8 + \
                            method_name_length * 2 + 8 + 8 +\
                              public_key_algorithm_name_length * 2 + 8 +\
                               public_key_to_be_used_for_authentication_length\
                                * 2 + 8:20 + user_name_length * 2 + 8 +\
                                 service_name_length * 2 + 8 +\
                                  method_name_length * 2 + 8 + 8 +\
                                   public_key_algorithm_name_length * 2 + 8 +\
                    public_key_to_be_used_for_authentication_length\
                                     * 2 + 8 + signature_length * 2]
                            resultlist.append((\
                            "public_key_to_be_used_for_authentication_length",
                    str(public_key_to_be_used_for_authentication_length)))
                            resultlist.append((\
                            "public_key_to_be_used_for_authentication",
                             self.get_ascii(\
                            public_key_to_be_used_for_authentication)))
                            resultlist.append(("signature_length",
                            str(signature_length)))
                            resultlist.append(("signature",
                             self.get_ascii(signature)))
                    if method_name.startswith("password"):
                        boolean = int(self.myresult[20 + user_name_length\
                         * 2 + 8 + service_name_length * 2 + 8 +\
                          method_name_length * 2:20 + user_name_length *\
                           2 + 8 + service_name_length * 2 + 8 +\
                            method_name_length * 2 + 8], 16)
                        resultlist.append(("boolean", boolean))
                        if boolean == 0:
                            plaintext_password_length = int(self.myresult[\
                            20 + user_name_length * 2 + 8 +\
                             service_name_length * 2 + 8 + method_name_length\
                              * 2 + 8:20 + user_name_length * 2 + 8 +\
                               service_name_length * 2 + 8 +\
                                method_name_length * 2 + 8 + 8], 16)
                            plaintext_password = self.myresult[20 +\
                             user_name_length * 2 + 8 + service_name_length\
                              * 2 + 8 + method_name_length * 2 + 8 + 8:20 +\
                               user_name_length * 2 + 8 + service_name_length\
                                * 2 + 8 + method_name_length * 2 + 8 + 8 +\
                                 plaintext_password_length * 2]
                            resultlist.append(("plaintext_password_length",
                             str(plaintext_password_length)))
                            resultlist.append(("plaintext_password",
                             self.get_ascii(plaintext_password)))
                        if boolean != 0:
                            plaintext_old_password_length =\
                             int(self.myresult[20 + user_name_length * 2 +\
                             8 + service_name_length * 2 + 8 +\
                              method_name_length * 2 + 8:20 +\
                               user_name_length * 2 + 8 +\
                                service_name_length * 2 + 8 +\
                                 method_name_length * 2 + 8 + 8], 16)
                            plaintext_old_password = self.myresult[\
                            20 + user_name_length * 2 + 8 +\
                             service_name_length * 2 + 8 +\
                              method_name_length * 2 + 8 + 8:20 +\
                               user_name_length * 2 + 8 +\
                                service_name_length * 2 + 8 +\
                                 method_name_length * 2 + 8 + 8 +\
                                  plaintext_old_password_length * 2]
                            plaintext_new_password_length = \
                            int(self.myresult[20 + user_name_length * 2 +\
                             8 + service_name_length * 2 + 8 +\
                              method_name_length * 2 + 8 + 8 +\
                               plaintext_old_password_length * 2:20\
                                + user_name_length * 2 + 8 +\
                                 service_name_length * 2 + 8 +\
                                  method_name_length * 2 + 8 + 8 +\
                                   plaintext_old_password_length * 2 + 8], 16)
                            plaintext_new_password = self.myresult[\
                            20 + user_name_length * 2 + 8 +\
                             service_name_length * 2 + 8 + method_name_length\
                             * 2 + 8 + 8 + plaintext_old_password_length\
                              * 2 + 8:20 + user_name_length * 2 + 8 +\
                               service_name_length * 2 + 8 +\
                                method_name_length * 2 + 8 + 8 +\
                                 plaintext_old_password_length * 2 +\
                                  plaintext_new_password_length * 2]
                            resultlist.append(("plaintext_old_password_length",
                             str(plaintext_old_password_length)))
                            resultlist.append(("plaintext_old_password",
                             plaintext_old_password))
                            resultlist.append(("plaintext_new_password_length",
                             str(plaintext_new_password_length)))
                            resultlist.append(("plaintext_new_password",
                             self.get_ascii(plaintext_new_password)))
                    if method_name.startswith("hostbased"):
                        public_key_algorithm_for_host_key_length =\
                         int(self.myresult[12:20], 16)
                        public_key_algorithm_for_host_key =\
                         self.myresult[20:20 +\
                         public_key_algorithm_for_host_key_length * 2]
                        public_host_key_and_cert_for_client_host_len =\
                         int(self.myresult[20 +\
                         public_key_algorithm_for_host_key_length * 2:20 +\
                          public_key_algorithm_for_host_key_length *\
                           2 + 8], 16)
                        public_host_key_and_certificates_for_client_host =\
                         self.myresult[20 +\
                         public_key_algorithm_for_host_key_length * 2 +\
                          8:20 + public_key_algorithm_for_host_key_length *\
                           2 + 8 +\
                            public_host_key_and_cert_for_client_host_len * 2]
                        client_host_name_length = int(self.myresult[20 +\
                         public_key_algorithm_for_host_key_length * 2 + 8 +\
                          public_host_key_and_cert_for_client_host_len\
                           * 2:20 + public_key_algorithm_for_host_key_length\
            * 2 + 8 + public_host_key_and_cert_for_client_host_len\
                     * 2 + 8], 16)
                        client_host_name = self.myresult[20 +\
                         public_key_algorithm_for_host_key_length * 2 + 8 +\
                    public_host_key_and_cert_for_client_host_len\
                     * 2 + 8:20 + public_key_algorithm_for_host_key_length\
            * 2 + 8 + public_host_key_and_cert_for_client_host_len\
             * 2 + 8 + client_host_name_length * 2]
                        user_name_on_the_client_host_length = int(\
                        self.myresult[20 +\
                     public_key_algorithm_for_host_key_length * 2 + 8 +\
                 public_host_key_and_cert_for_client_host_len\
            * 2 + 8 + client_host_name_length * 2:20 +\
             public_key_algorithm_for_host_key_length * 2 + 8 +\
              public_host_key_and_cert_for_client_host_len\
               * 2 + 8 + client_host_name_length * 2 + 8], 16)
                        user_name_on_the_client_host = self.myresult[20\
                 + public_key_algorithm_for_host_key_length * 2 + 8 +\
         public_host_key_and_cert_for_client_host_len * 2 +\
          8 + client_host_name_length * 2 + 8:20 +\
           public_key_algorithm_for_host_key_length * 2 + 8 +\
            public_host_key_and_cert_for_client_host_len * 2 + 8 +\
             client_host_name_length * 2 + 8 +\
              user_name_on_the_client_host_length * 2]
                        signature_length = int(self.myresult[20 +\
                 public_key_algorithm_for_host_key_length * 2 + 8 +\
                  public_host_key_and_cert_for_client_host_len\
         * 2 + 8 + client_host_name_length * 2 + 8 +\
          user_name_on_the_client_host_length * 2:20 +\
           public_key_algorithm_for_host_key_length * 2 + 8 +\
            public_host_key_and_cert_for_client_host_len * 2 + 8 +\
             client_host_name_length * 2 + 8 +\
              user_name_on_the_client_host_length * 2 + 8], 16)
                        signature = self.myresult[20 +\
            public_key_algorithm_for_host_key_length * 2 + 8 +\
             public_host_key_and_cert_for_client_host_len * 2 +\
              8 + client_host_name_length * 2 + 8 +\
               user_name_on_the_client_host_length * 2 + 8:20 +\
                public_key_algorithm_for_host_key_length * 2 + 8 +\
                 public_host_key_and_cert_for_client_host_len *\
                  2 + 8 + client_host_name_length * 2 + 8 +\
                   user_name_on_the_client_host_length * 2 + 8 +\
                    signature_length * 2]
                        resultlist.append(("public_key_algorithm_for\
                        _host_key_length",
                        str(public_key_algorithm_for_host_key_length)))
                        resultlist.append(("public_key_algorithm_for_host_key",
                        self.get_ascii(public_key_algorithm_for_host_key)))
                        resultlist.append(\
                    ("public_host_key_and_certificates_for_client_host_length",
                         str(\
                    public_host_key_and_cert_for_client_host_len)))
                        resultlist.append(\
                        ("public_host_key_and_certificates_for_client_host",
                         self.get_ascii(\
                        public_host_key_and_certificates_for_client_host)))
                        resultlist.append(("client_host_name_length",
                         str(client_host_name_length)))
                        resultlist.append(("client_host_name",
                         self.get_ascii(client_host_name)))
                        resultlist.append(\
                        ("user_name_on_the_client_host_length",\
                         str(user_name_on_the_client_host_length)))
                        resultlist.append(("user_name_on_the_client_host",
                         self.get_ascii(user_name_on_the_client_host)))
                        resultlist.append(("signature_length",
                         str(signature_length)))
                        resultlist.append(("signature",
                         self.get_ascii(signature)))
                    else:
                        method_specific_fields_length = int(self.myresult[\
        20 + user_name_length * 2 + 8 + service_name_length * 2 + 8 +\
         method_name_length * 2:20 + user_name_length * 2 + 8 +\
          service_name_length * 2 + 8 + method_name_length * 2 + 8], 16)
                        method_specific_fields = self.myresult[\
        20 + user_name_length * 2 + 8 + service_name_length * 2 + 8 +\
         method_name_length * 2 + 8:20 + user_name_length * 2 + 8 +\
          service_name_length * 2 + 8 + method_name_length * 2 + 8 +\
           method_specific_fields_length * 2]
                        resultlist.append(("method_specific_fields_length",
                         str(method_specific_fields_length)))
                        resultlist.append(("method_specific_fields",
                         self.get_ascii(method_specific_fields)))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                        pkt.underlayer.underlayer.fields["src"],\
                                      pkt.underlayer.underlayer.fields["dst"],\
                                      pkt.underlayer.fields["sport"],\
                                      pkt.underlayer.fields["dport"])\
                 and opcode.startswith("SSH_MSG_USERAUTH_FAILURE"):
                try:
                    authentications_that_can_continue_length =\
                     int(self.myresult[12:20], 16)
                    authentications_that_can_continue =\
        self.myresult[20:20 + authentications_that_can_continue_length * 2]
                    partial_success_boolean = int(self.myresult[20 +\
     authentications_that_can_continue_length * 2:20 +\
      authentications_that_can_continue_length * 2 + 8], 16)
                    resultlist.append(\
                ("authentications_that_can_continue_length",
                     str(authentications_that_can_continue_length)))
                    resultlist.append(("authentications_that_can_continue",
                     authentications_that_can_continue))
                    resultlist.append(("partial_success_boolean",
                     partial_success_boolean))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],\
      pkt.underlayer.underlayer.fields["dst"],\
      pkt.underlayer.fields["sport"],\
      pkt.underlayer.fields["dport"])\
       and opcode.startswith("SSH_MSG_USERAUTH_BANNER"):
                try:
                    message_length = int(self.myresult[12:20], 16)
                    message = self.myresult[20:20 + message_length * 2]
                    language_tag_length = int(self.myresult[20 +\
                     message_length * 2:20 + message_length * 2 + 8], 16)
                    language_tag = self.myresult[20 + message_length * 2\
                  + 8:20 + message_length * 2 + 8 + language_tag_length * 2]
                    resultlist.append(("message_length", str(message_length)))
                    resultlist.append(("message", self.get_ascii(message)))
                    resultlist.append(("language_tag_length",
                     str(language_tag_length)))
                    resultlist.append(("language_tag",
                     self.get_ascii(language_tag)))
                    self.found = True
                except Exception:
                    self.found = False

            if not is_encrypted_session(\
                pkt.underlayer.underlayer.fields["src"],
                    pkt.underlayer.underlayer.fields["dst"],
                    pkt.underlayer.fields["sport"],
                    pkt.underlayer.fields["dport"])\
                     and opcode.startswith("SSH_MSG_KEXINIT"):
                try:
                    cookie = base64.standard_b64encode(self.myresult[12:44])
                    kex_algorithms_length = int(self.myresult[44:52], 16)
                    kex_algorithms = self.get_ascii(self.myresult[52:52 +\
                     kex_algorithms_length * 2])
                    server_host_key_algorithms_length = int(self.myresult[52 +\
                     kex_algorithms_length * 2:52 + kex_algorithms_length\
                      * 2 + 8], 16)
                    server_host_key_algorithms = self.get_ascii(self.myresult[\
                    52 + kex_algorithms_length * 2 + 8:52 +\
                 kex_algorithms_length * 2 + 8 +\
                  server_host_key_algorithms_length * 2])
                    encryption_algorithms_client_to_server_length = int(\
                    self.myresult[52 + kex_algorithms_length * 2 + 8 +\
                    server_host_key_algorithms_length * 2:52 +\
                     kex_algorithms_length * 2 + 8 +\
                      server_host_key_algorithms_length * 2 + 8], 16)
                    encryption_algorithms_client_to_server = self.get_ascii(\
                    self.myresult[52 + kex_algorithms_length * 2 + 8 +\
                     server_host_key_algorithms_length * 2 + 8:52 +\
                     kex_algorithms_length * 2 + 8 +\
                      server_host_key_algorithms_length * 2 + 8 +\
                       encryption_algorithms_client_to_server_length * 2])
                    encryption_algorithms_server_to_client_length = int(\
                    self.myresult[52 + kex_algorithms_length * 2 + 8 +\
                     server_host_key_algorithms_length * 2 + 8 +\
                      encryption_algorithms_client_to_server_length * 2:52 +\
                       kex_algorithms_length * 2 + 8 +\
                        server_host_key_algorithms_length * 2 + 8 +\
                         encryption_algorithms_client_to_server_length *\
                          2 + 8], 16)
                    encryption_algorithms_server_to_client = self.get_ascii(\
                    self.myresult[52 + kex_algorithms_length * 2 + 8 +\
                     server_host_key_algorithms_length * 2 + 8 +\
                      encryption_algorithms_client_to_server_length * 2 +\
                       8:52 + kex_algorithms_length * 2 + 8 +\
                        server_host_key_algorithms_length * 2 + 8 +\
                         encryption_algorithms_client_to_server_length * 2 +\
                          8 + encryption_algorithms_server_to_client_length\
                           * 2])
                    mac_algorithms_client_to_server_length = int(\
        self.myresult[52 + kex_algorithms_length * 2 + 8 +\
         server_host_key_algorithms_length * 2 + 8 +\
          encryption_algorithms_client_to_server_length * 2 + 8 +\
           encryption_algorithms_server_to_client_length * 2:52 +\
            kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
             * 2 + 8 + encryption_algorithms_client_to_server_length * 2 +\
              8 + encryption_algorithms_server_to_client_length * 2 + 8], 16)
                    mac_algorithms_client_to_server = self.get_ascii(\
        self.myresult[52 + kex_algorithms_length * 2 + 8 +\
         server_host_key_algorithms_length * 2 + 8 +\
          encryption_algorithms_client_to_server_length * 2 + 8 +\
           encryption_algorithms_server_to_client_length * 2 + 8:52 +\
            kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
             * 2 + 8 + encryption_algorithms_client_to_server_length * 2 +\
              8 + encryption_algorithms_server_to_client_length * 2 + 8 +\
               mac_algorithms_client_to_server_length * 2])
                    mac_algorithms_server_to_client_length = int(\
        self.myresult[52 + kex_algorithms_length * 2 + 8 +\
         server_host_key_algorithms_length * 2 + 8 +\
          encryption_algorithms_client_to_server_length * 2 + 8 +\
           encryption_algorithms_server_to_client_length * 2 + 8 +\
            mac_algorithms_client_to_server_length * 2:52 +\
        kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
         * 2 + 8 + encryption_algorithms_client_to_server_length * 2 +\
          8 + encryption_algorithms_server_to_client_length * 2 + 8 +\
           mac_algorithms_client_to_server_length * 2 + 8], 16)
                    mac_algorithms_server_to_client = self.get_ascii(\
        self.myresult[52 + kex_algorithms_length * 2 + 8 +\
     server_host_key_algorithms_length * 2 + 8 +\
      encryption_algorithms_client_to_server_length * 2 + 8 +\
       encryption_algorithms_server_to_client_length * 2 + 8 +\
        mac_algorithms_client_to_server_length * 2 + 8:52 +\
         kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
          * 2 + 8 + encryption_algorithms_client_to_server_length * 2 +\
           8 + encryption_algorithms_server_to_client_length * 2 + 8 +\
            mac_algorithms_client_to_server_length * 2 + 8 +\
             mac_algorithms_server_to_client_length * 2])
                    compression_algorithms_client_to_server_length =\
                     int(self.myresult[52 + kex_algorithms_length * 2 + 8 +\
         server_host_key_algorithms_length * 2 + 8 +\
          encryption_algorithms_client_to_server_length * 2 + 8 +\
           encryption_algorithms_server_to_client_length * 2 + 8 +\
            mac_algorithms_client_to_server_length * 2 + 8 +\
             mac_algorithms_server_to_client_length * 2:52 +\
        kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length *\
         2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
          encryption_algorithms_server_to_client_length * 2 + 8 +\
           mac_algorithms_client_to_server_length * 2 + 8 +\
            mac_algorithms_server_to_client_length * 2 + 8], 16)
                    compression_algorithms_client_to_server = self.get_ascii(\
                    self.myresult[52 + kex_algorithms_length * 2 + 8 +\
                server_host_key_algorithms_length * 2 + 8 +\
                 encryption_algorithms_client_to_server_length * 2 + 8 +\
                  encryption_algorithms_server_to_client_length * 2 + 8 +\
                   mac_algorithms_client_to_server_length * 2 + 8 +\
                    mac_algorithms_server_to_client_length * 2 + 8:52 +\
                     kex_algorithms_length * 2 + 8 +\
                      server_host_key_algorithms_length * 2 + 8 +\
                       encryption_algorithms_client_to_server_length * 2 + 8 +\
                        encryption_algorithms_server_to_client_length\
                         * 2 + 8 + mac_algorithms_client_to_server_length\
                          * 2 + 8 + mac_algorithms_server_to_client_length\
                           * 2 + 8 + \
                        compression_algorithms_client_to_server_length * 2])
                    compression_algorithms_server_to_client_length = int(\
            self.myresult[52 + kex_algorithms_length * 2 + 8 +\
             server_host_key_algorithms_length * 2 + 8 +\
              encryption_algorithms_client_to_server_length * 2 + 8 +\
               encryption_algorithms_server_to_client_length * 2 + 8 +\
                mac_algorithms_client_to_server_length * 2 + 8 +\
                 mac_algorithms_server_to_client_length * 2 + 8 +\
                  compression_algorithms_client_to_server_length * 2:52 +\
                   kex_algorithms_length * 2 + 8 +\
         server_host_key_algorithms_length * 2 + 8 +\
          encryption_algorithms_client_to_server_length * 2 + 8 +\
           encryption_algorithms_server_to_client_length * 2 + 8 +\
            mac_algorithms_client_to_server_length * 2 + 8 +\
             mac_algorithms_server_to_client_length * 2 + 8 +\
              compression_algorithms_client_to_server_length * 2 + 8], 16)
                    compression_algorithms_server_to_client = self.get_ascii(\
    self.myresult[52 + kex_algorithms_length * 2 + 8 +\
     server_host_key_algorithms_length * 2 + 8 +\
      encryption_algorithms_client_to_server_length * 2 + 8 +\
       encryption_algorithms_server_to_client_length * 2 + 8 +\
        mac_algorithms_client_to_server_length * 2 + 8 +\
         mac_algorithms_server_to_client_length * 2 + 8 +\
          compression_algorithms_client_to_server_length * 2 + 8:52 +\
           kex_algorithms_length * 2 + 8 + \
           server_host_key_algorithms_length * 2 +\
            8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
             encryption_algorithms_server_to_client_length * 2 + 8 +\
              mac_algorithms_client_to_server_length * 2 + 8 +\
               mac_algorithms_server_to_client_length * 2 + 8 +\
                compression_algorithms_client_to_server_length * 2 + 8 +\
                 compression_algorithms_server_to_client_length * 2])
                    languages_client_to_server_length = int(self.myresult[\
    52 + kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
     * 2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
      encryption_algorithms_server_to_client_length * 2 + 8 +\
       mac_algorithms_client_to_server_length * 2 + 8 +\
        mac_algorithms_server_to_client_length * 2 + 8 +\
         compression_algorithms_client_to_server_length * 2 + 8 +\
          compression_algorithms_server_to_client_length * 2:52 +\
           kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
            * 2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
             encryption_algorithms_server_to_client_length * 2 + 8 +\
              mac_algorithms_client_to_server_length * 2 + 8 +\
               mac_algorithms_server_to_client_length * 2 + 8 +\
                compression_algorithms_client_to_server_length * 2 + 8 +\
                 compression_algorithms_server_to_client_length * 2 + 8], 16)
                    languages_client_to_server = self.get_ascii(self.myresult[\
     52 + kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
      * 2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
       encryption_algorithms_server_to_client_length * 2 + 8 +\
        mac_algorithms_client_to_server_length * 2 + 8 +\
         mac_algorithms_server_to_client_length * 2 + 8 +\
          compression_algorithms_client_to_server_length * 2 + 8 +\
           compression_algorithms_server_to_client_length * 2 + 8:52 +\
            kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
             * 2 + 8 + encryption_algorithms_client_to_server_length * 2 +\
              8 + encryption_algorithms_server_to_client_length * 2 + 8 +\
               mac_algorithms_client_to_server_length * 2 + 8 +\
                mac_algorithms_server_to_client_length * 2 + 8 +\
                 compression_algorithms_client_to_server_length *\
                  2 + 8 + compression_algorithms_server_to_client_length *\
                   2 + 8 + languages_client_to_server_length * 2])
                    languages_client_to_server_length = int(self.myresult[52 +\
     kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length * 2 +\
      8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
       encryption_algorithms_server_to_client_length * 2 + 8 +\
        mac_algorithms_client_to_server_length * 2 + 8 +\
         mac_algorithms_server_to_client_length * 2 + 8 +\
          compression_algorithms_client_to_server_length *\
           2 + 8 + compression_algorithms_server_to_client_length *\
            2 + 8 + languages_client_to_server_length * 2:52 +\
             kex_algorithms_length * 2 + 8 +\
              server_host_key_algorithms_length * 2 + 8 +\
               encryption_algorithms_client_to_server_length * 2 + 8 +\
                encryption_algorithms_server_to_client_length * 2 + 8 +\
                 mac_algorithms_client_to_server_length * 2 + 8 +\
                  mac_algorithms_server_to_client_length * 2 + 8 +\
                   compression_algorithms_client_to_server_length * 2 +\
                    8 + compression_algorithms_server_to_client_length * 2 +\
                     8 + languages_client_to_server_length * 2 + 8], 16)
                    languages_client_to_server = self.get_ascii(self.myresult[\
    52 + kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length *\
     2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
      encryption_algorithms_server_to_client_length * 2 + 8 +\
       mac_algorithms_client_to_server_length * 2 + 8 +\
        mac_algorithms_server_to_client_length * 2 + 8 +\
         compression_algorithms_client_to_server_length * 2 +\
          8 + compression_algorithms_server_to_client_length * 2 + 8 +\
           languages_client_to_server_length * 2 + 8:52 +\
            kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
             * 2 + 8 + encryption_algorithms_client_to_server_length * 2 +\
              8 + encryption_algorithms_server_to_client_length * 2 + 8 +\
               mac_algorithms_client_to_server_length * 2 + 8 +\
                mac_algorithms_server_to_client_length * 2 + 8 +\
                 compression_algorithms_client_to_server_length * 2 + 8 +\
                  compression_algorithms_server_to_client_length * 2 + 8 +\
                   languages_client_to_server_length * 2 + 8 +\
                    languages_client_to_server_length * 2])
                    languages_server_to_client_length = int(self.myresult[\
    52 + kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length *\
     2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
      encryption_algorithms_server_to_client_length * 2 + 8 +\
       mac_algorithms_client_to_server_length * 2 + 8 +\
        mac_algorithms_server_to_client_length * 2 + 8 +\
         compression_algorithms_client_to_server_length * 2 + 8 +\
          compression_algorithms_server_to_client_length * 2 + 8 +\
           languages_client_to_server_length * 2 + 8 +\
            languages_client_to_server_length * 2:52 + kex_algorithms_length *\
             2 + 8 + server_host_key_algorithms_length * 2 + 8 +\
              encryption_algorithms_client_to_server_length * 2 + 8 +\
               encryption_algorithms_server_to_client_length * 2 + 8 +\
                mac_algorithms_client_to_server_length * 2 + 8 +\
                 mac_algorithms_server_to_client_length * 2 + 8 +\
                  compression_algorithms_client_to_server_length * 2 + 8 +\
                   compression_algorithms_server_to_client_length * 2 + 8 +\
                    languages_client_to_server_length * 2 + 8 +\
                     languages_client_to_server_length * 2 + 8], 16)
                    languages_server_to_client = self.get_ascii(\
    self.myresult[52 + kex_algorithms_length * 2 + 8 +\
     server_host_key_algorithms_length * 2 + 8 +\
      encryption_algorithms_client_to_server_length * 2 + 8 +\
       encryption_algorithms_server_to_client_length * 2 + 8 +\
        mac_algorithms_client_to_server_length * 2 + 8 +\
         mac_algorithms_server_to_client_length * 2 + 8 +\
          compression_algorithms_client_to_server_length * 2 + 8 +\
           compression_algorithms_server_to_client_length * 2 + 8 +\
            languages_client_to_server_length * 2 + 8 +\
             languages_client_to_server_length * 2 + 8:52 +\
              kex_algorithms_length * 2 + 8 +\
               server_host_key_algorithms_length * 2 + 8 +\
                encryption_algorithms_client_to_server_length * 2 + 8 +\
                 encryption_algorithms_server_to_client_length * 2 + 8 +\
                  mac_algorithms_client_to_server_length * 2 + 8 +\
                   mac_algorithms_server_to_client_length * 2 + 8 +\
                    compression_algorithms_client_to_server_length * 2 +\
                     8 + compression_algorithms_server_to_client_length *\
                      2 + 8 + languages_client_to_server_length * 2 + 8 +\
                       languages_client_to_server_length * 2 + 8 +\
                        languages_server_to_client_length * 2])
                    first_kex_packet_follows_boolean = self.myresult[\
    52 + kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
     * 2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
      encryption_algorithms_server_to_client_length * 2 + 8 +\
       mac_algorithms_client_to_server_length * 2 + 8 +\
        mac_algorithms_server_to_client_length * 2 + 8 +\
         compression_algorithms_client_to_server_length * 2 + 8 +\
          compression_algorithms_server_to_client_length * 2 + 8 +\
           languages_client_to_server_length * 2 + 8 +\
            languages_client_to_server_length * 2 + 8 +\
             languages_server_to_client_length * 2:52 +\
        kex_algorithms_length * 2 + 8 + server_host_key_algorithms_length\
         * 2 + 8 + encryption_algorithms_client_to_server_length * 2 + 8 +\
          encryption_algorithms_server_to_client_length * 2 + 8 +\
           mac_algorithms_client_to_server_length * 2 + 8 +\
            mac_algorithms_server_to_client_length * 2 + 8 +\
             compression_algorithms_client_to_server_length * 2 + 8 +\
              compression_algorithms_server_to_client_length * 2 + 8 +\
               languages_client_to_server_length * 2 + 8 +\
                languages_client_to_server_length * 2 + 8 +\
                 languages_server_to_client_length * 2 + 2]
                    reserved = self.myresult[52 + kex_algorithms_length *\
         2 + 8 + server_host_key_algorithms_length * 2 + 8 +\
          encryption_algorithms_client_to_server_length * 2 + 8 +\
           encryption_algorithms_server_to_client_length * 2 + 8 +\
            mac_algorithms_client_to_server_length * 2 + 8 +\
             mac_algorithms_server_to_client_length * 2 + 8 +\
              compression_algorithms_client_to_server_length * 2 + 8 +\
               compression_algorithms_server_to_client_length * 2 + 8 +\
                languages_client_to_server_length * 2 + 8 +\
                 languages_client_to_server_length * 2 + 8 +\
                  languages_server_to_client_length * 2 + 2:52 +\
                   kex_algorithms_length * 2 + 8 +\
                    server_host_key_algorithms_length * 2 + 8 +\
                     encryption_algorithms_client_to_server_length * 2 + 8 +\
                      encryption_algorithms_server_to_client_length * 2 + 8 +\
                       mac_algorithms_client_to_server_length * 2 + 8 +\
                        mac_algorithms_server_to_client_length * 2 + 8 +\
                         compression_algorithms_client_to_server_length * 2 +\
                          8 + compression_algorithms_server_to_client_length\
                           * 2 + 8 + languages_client_to_server_length * 2 +\
                            8 + languages_client_to_server_length * 2 + 8 +\
                             languages_server_to_client_length * 2 + 2 + 8]
                    ctosmac = mac_algorithms_client_to_server.split(",")
                    stocmac = mac_algorithms_server_to_client.split(",")
                    i = 0
                    j = 0
                    while i < len(ctosmac):
                        while j < len(stocmac):
                            if ctosmac[i].startswith(stocmac[j]):
                                if ctosmac[i].startswith("hmac-sha1"):
                                    create_session(\
                    pkt.underlayer.underlayer.fields["src"],
                    pkt.underlayer.underlayer.fields["dst"],
                    pkt.underlayer.fields["sport"],
                    pkt.underlayer.fields["dport"], 20)
                                if ctosmac[i].startswith("hmac-sha1-96"):
                                    create_session(\
                    pkt.underlayer.underlayer.fields["src"],
                    pkt.underlayer.underlayer.fields["dst"],
                    pkt.underlayer.fields["sport"],
                    pkt.underlayer.fields["dport"], 20)
                                if ctosmac[i].startswith("hmac-md5"):
                                    create_session(\
                    pkt.underlayer.underlayer.fields["src"],
                    pkt.underlayer.underlayer.fields["dst"],
                    pkt.underlayer.fields["sport"],
                    pkt.underlayer.fields["dport"], 16)
                                if ctosmac[i].startswith("hmac-md5-96"):
                                    create_session(\
                    pkt.underlayer.underlayer.fields["src"],
                    pkt.underlayer.underlayer.fields["dst"],
                    pkt.underlayer.fields["sport"],
                    pkt.underlayer.fields["dport"], 16)
                                if ctosmac[i].startswith("none"):
                                    create_session(\
                    pkt.underlayer.underlayer.fields["src"],
                    pkt.underlayer.underlayer.fields["dst"],
                    pkt.underlayer.fields["sport"],
                    pkt.underlayer.fields["dport"], 0)
                            j = j + 1
                        i = i + 1

                    resultlist.append(("cookie", cookie))
                    resultlist.append(\
                    ("kex_algorithms_length", str(kex_algorithms_length)))
                    resultlist.append(("kex_algorithms", kex_algorithms))
                    resultlist.append(\
        ("server_host_key_algorithms_length",\
          str(server_host_key_algorithms_length)))
                    resultlist.append(\
        ("server_host_key_algorithms", server_host_key_algorithms))
                    resultlist.append(\
("encryption_algorithms_client_to_server_length",\
 str(encryption_algorithms_client_to_server_length)))
                    resultlist.append(\
        ("encryption_algorithms_client_to_server",\
          encryption_algorithms_client_to_server))
                    resultlist.append(\
        ("encryption_algorithms_server_to_client_length",\
          str(encryption_algorithms_server_to_client_length)))
                    resultlist.append(\
    ("encryption_algorithms_server_to_client",\
      encryption_algorithms_server_to_client))
                    resultlist.append(\
        ("mac_algorithms_client_to_server_length",\
          str(mac_algorithms_client_to_server_length)))
                    resultlist.append(\
        ("mac_algorithms_client_to_server",\
          mac_algorithms_client_to_server))
                    resultlist.append(\
        ("mac_algorithms_server_to_client_length",\
          str(mac_algorithms_server_to_client_length)))
                    resultlist.append(("mac_algorithms_server_to_client",
                     mac_algorithms_server_to_client))
                    resultlist.append(\
            ("compression_algorithms_client_to_server_length", str(\
                    compression_algorithms_client_to_server_length)))
                    resultlist.append(\
            ("compression_algorithms_client_to_server",\
              compression_algorithms_client_to_server))
                    resultlist.append(\
            ("compression_algorithms_server_to_client_length", str(\
                    compression_algorithms_server_to_client_length)))
                    resultlist.append(\
            ("compression_algorithms_server_to_client",\
              compression_algorithms_server_to_client))
                    resultlist.append(("languages_client_to_server_length",
                     str(languages_client_to_server_length)))
                    resultlist.append(("languages_client_to_server",
                     languages_client_to_server))
                    resultlist.append(("languages_server_to_client_length",
                     str(languages_server_to_client_length)))
                    resultlist.append(("languages_server_to_client",
                     languages_server_to_client))
                    resultlist.append(("first_kex_packet_follows_boolean",
                     first_kex_packet_follows_boolean))
                    resultlist.append(("reserved", reserved))
                    self.found = True
                except Exception:
                    #self.found = False
                    None

            if not self.found and not is_encrypted_session(\
            pkt.underlayer.underlayer.fields["src"],
            pkt.underlayer.underlayer.fields["dst"],
            pkt.underlayer.fields["sport"],
            pkt.underlayer.fields["dport"]):
                payload = base64.standard_b64encode(\
                self.get_ascii(self.myresult[12:payloadl * 2]))
                resultlist.append(("payload", payload))

            self.found = False
            if not is_encrypted_session(\
                            pkt.underlayer.underlayer.fields["src"],\
                            pkt.underlayer.underlayer.fields["dst"],\
                                      pkt.underlayer.fields["sport"],\
                                      pkt.underlayer.fields["dport"]):
                resultlist.append(("padding", padding))
                if len(self.myresult) > (10 + payloadl * 2 + int(padl) * 2):
                    resultlist.append(("MAC", self.myresult[10 + payloadl *\
                                         2 + int(padl) * 2:]))
            result_str = ""
            for item in resultlist:
                if len(result_str) == 0:
                    result_str = item[0] + ": " + item[1]
                else:
                    result_str = result_str + ", " + item[0] + ": " + item[1]
            return "", result_str
        return "", ""


class SSH(Packet):
    """
    class for handling the ssh packets
    @attention: this class inherets Packet
    """
    name = "ssh"
    fields_desc = [SSHField("sshpayload", "")]

bind_layers(TCP, SSH, dport=22)
bind_layers(TCP, SSH, sport=22)
