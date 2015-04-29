import base64
import os
import string
import random
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
import dissector


downloaded_files = []


def name_generator(size=9, chars=string.ascii_uppercase + string.digits):
    """
    this method is for generating a randndom name for the downloaded files
    @param size: number of random characters
    @param chars: type of the random characters
    """
    return ''.join(random.choice(chars) for x in range(size))


def clean_file_name(name, path):
    """
    this method is for cleaning the carved file name if it has some special chars
    which is not allowed in most of the operating systems or if the specified folder
    in path variable has another file has the same name.
    @param name: the carved file name
    @param path: the directory path
    """
    ls = list(name)
    result = ""
    length = len(ls)
    files = os.listdir(path)
    if len(name) > 25 or name in files or name == "NoName":
        return name_generator()
    i = 0
    while i < length:
        if ls[i].isalnum() or ls[i] == ".":
            result = result + ls[i]
        i = i + 1
    if len(result) > 0:
        return result
    else:
        return name_generator()


def add_file(Src, Dst, SPort, DPort, name, seq):
    """
    this method is for storing the carved file name.
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param name: the carved file name
    @param seq: sequence number
    """
    downloaded_files.append((Src, Dst, SPort, DPort, name[1:], seq))


def get_file(Src, Dst, SPort, DPort, ack):
    """
    this method is for retrieving the stored file name
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    @param DPort: destination port number
    @param ack: acknowledgment number
    """
    for element in downloaded_files:
        if  Src == element[1] and Dst == element[0] and\
         SPort == element[3] and DPort == element[2] and\
          ack == element[5]:
            return element[4]
    return "NoName"


class HTTPReqField(StrField):
    """
    field class for handling http requests
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "HTTPReqField"

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
              pkt.underlayer.fields["sport"], pkt.underlayer.fields["dport"],\
               pkt.underlayer.fields["seq"], s)
        if not cstream == -1:
            s = cstream
        if pkt.underlayer.name == "TCP" and cstream == -1:
            return "", ""
        remain = ""
        value = ""
        if self.name == "request-line: ":
            ls = s.splitlines(True)
            f = ls[0].split()
            length = len(f)
            if length == 3:
                value = "Method:" + f[0] + ", Request-URI:" +\
                        f[1] + ", HTTP-Version:" + f[2]
                HTTPMethodsRFC2616 = ['get','post','options','head','put','delete','trace','connect'] 
                #HTTP methods as per rfc2616 http://www.ietf.org/rfc/rfc2616
                #There are other methods in other RFCs but nobody cares about those.
                if f[0].lower() in HTTPMethodsRFC2616:
                    add_file(pkt.underlayer.underlayer.fields["src"],\
                              pkt.underlayer.underlayer.fields["dst"],\
                               pkt.underlayer.fields["sport"],\
                                pkt.underlayer.fields["dport"], f[1],\
                                 pkt.underlayer.fields["seq"] + len(s))
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
                return remain, value
            return s, ""


class HTTPResField(StrField):
    """
    field class for handling http requests
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "HTTPResField"
    fin = False

    def get_code_msg(self, cn):
        """
        method returns the message for the http code number
        @param cn: code number
    """
        codes = {
  "100": "Continue",
  "101": "Switching Protocols",
  "102": "Processing",
  "199": "Informational - Others",
  "200": "OK",
  "201": "Created",
  "202": "Accepted",
  "203": "Non-Authoritative Information",
  "204": "No Content",
  "205": "Reset Content",
  "206": "Partial Content",
  "207": "Multi-Status",
  "299": "Success - Others",
  "300": "Multiple Choices",
  "301": "Moved Permanently",
  "302": "Moved Temporarily",
  "303": "See Other",
  "304": "Not Modified",
  "305": "Use Proxy",
  "306": "(Unused)",
  "307": "Temporary Redirect",
  "399": "Redirection - Others",
  "400": "Bad Request",
  "401": "Unauthorized",
  "402": "Payment Required",
  "403": "Forbidden",
  "404": "Not Found",
  "405": "Method Not Allowed",
  "406": "Not Acceptable",
  "407": "Proxy Authentication Required",
  "408": "Request Time-out",
  "409": "Conflict",
  "410": "Gone",
  "411": "Length Required",
  "412": "Precondition Failed",
  "413": "Request Entity Too Large",
  "414": "Request-URI Too Large",
  "415": "Unsupported Media Type",
  "416": "Requested Range Not Satisfiable",
  "417": "Expectation Failed",
  "422": "Unprocessable Entity",
  "423": "Locked",
  "424": "Failed Dependency",
  "499": "Client Error - Others",
  "500": "Internal Server Error",
  "501": "Not Implemented",
  "502": "Bad Gateway",
  "503": "Service Unavailable",
  "504": "Gateway Time-out",
  "505": "HTTP Version not supported",
  "599": "Server Error - Others"}

        if cn in codes:
            return codes[cn]
        return ""

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
        seq = pkt.underlayer.fields["seq"]
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
        if pkt.underlayer.name == "TCP" and cstream == -1:
            return "", ""
        remain = ""
        value = ""
        if self.name == "status-line: " and s.startswith("HTTP/"):
            ls = s.splitlines(True)
            f = ls[0].split()
            length = len(f)
            if length == 3:
                value = "HTTP-Version:" + f[0] + ", Status-Code:" +\
                        f[1] + ", Reason-Phrase:" + f[2]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
                return remain, value
        return s, ""


#class HTTPMsgField(XByteField):
class HTTPMsgField(XByteField):
    """
    field class for handling http body
    @attention: it inherets XByteField from Scapy library
    """
    holds_packets = 1
    name = "HTTPMsgField"
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
        name = get_file(pkt.underlayer.underlayer.fields["src"],\
                         pkt.underlayer.underlayer.fields["dst"],\
                          pkt.underlayer.fields["sport"],\
                           pkt.underlayer.fields["dport"],\
                            pkt.underlayer.fields["ack"])
        if pkt.underlayer.fields["sport"] == 80:
            if not dissector.Dissector.default_download_folder_changed:
                cwd = os.getcwd() + "/downloaded/"
                try:
                    os.mkdir("downloaded")
                except:
                    None
                f = open(cwd + clean_file_name(name, cwd), "wb")
            else:
                f = open(dissector.Dissector.path +\
                 clean_file_name(name, dissector.Dissector.path), "wb")
            f.write(s)
            f.close()
        self.myresult = ""
        for c in s:
            self.myresult = self.myresult + base64.standard_b64encode(c)

        if self.myresult[-1:] == " ":
            self.myresult = self.myresult.rstrip()
        return "", self.myresult


class HTTPField(StrField):
    """
    field class for handling http fields
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    name = "HTTPField"

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
                elif element != "\r\n"\
                 and (": " in element[:10])\
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
                            unknown = False
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
                return remain, value
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


class HTTPRequest(Packet):
    """
    class for handling http requests
    @attention: it inherets Packet from Scapy library
    """
    name = "http"
    fields_desc = [HTTPReqField("request-line: ", "", "H"),
                    HTTPField("cache-control: ", "", "H"),
                    HTTPField("connection: ", "", "H"),
                     HTTPField("date: ", "", "H"),
                    HTTPField("pragma: ", "", "H"),
                     HTTPField("trailer: ", "", "H"),
                    HTTPField("transfer-encoding: ", "", "H"),
                     HTTPField("upgrade: ", "", "H"),
                     HTTPField("dnt: ", "", "H"),
                     HTTPField("x-requested-with: ", "", "H"),
                    HTTPField("via: ", "", "H"),
                     HTTPField("Warning: ", "", "H"),
                    HTTPField("accept: ", "", "H"),
                     HTTPField("accept-encoding: ", "", "H"),
                    HTTPField("accept-language: ", "", "H"),
                    HTTPField("content-length: ", "", "H"),
                     HTTPField("accept-charset: ", "", "H"),
                    HTTPField("expect: ", "", "H"),
                     HTTPField("authorization: ", "", "H"),
                    HTTPField("accept-datetime: ", "", "H"),
                     HTTPField("from: ", "", "H"),
                    HTTPField("host: ", "", "H"),
                     HTTPField("if-match: ", "", "H"),
                    HTTPField("if-modified-since: ", "", "H"),
                     HTTPField("iIf-none-match: ", "", "H"),
                    HTTPField("if-range: ", "", "H"),
                     HTTPField("if-unmodified-since: ", "", "H"),
                    HTTPField("max-forwards: ", "", "H"),
                     HTTPField("proxy-authorization: ", "", "H"),
                    HTTPField("range: ", "", "H"),
                     HTTPField("referer: ", "", "H"),
                    HTTPField("te: ", "", "H"),
                     HTTPField("user-agent: ", "", "H"),
                    HTTPField("link: ", "", "H"),
                     HTTPField("mime-version: ", "", "H"),
                    HTTPField("title: ", "", "H"),
                     HTTPField("uri: ", "", "H"),
                    HTTPField("cookie: ", "", "H"),
                     HTTPField("set-cookie: ", "", "H"),
                    HTTPField("x-forwarded-for: ", "", "H"),
                     HTTPField("keep-alive: ", "", "H"),
                    HTTPField("unknown-header(s): ", "", "H"),
                     HTTPMsgField("message-body: ", "")]


class HTTPResponse(Packet):
    """
    class for handling http responses
    @attention: it inherets Packet from Scapy library
    """
    name = "http"
    fields_desc = [HTTPResField("status-line: ", "", "H"),#responses123
                    HTTPField("cache-control: ", "", "H"),
                    HTTPField("connection: ", "", "H"),
                     HTTPField("date: ", "", "H"),
                    HTTPField("pragma: ", "", "H"),
                    HTTPField("access-control-allow-origin: ", "", "H"),
                     HTTPField("trailer: ", "", "H"),
                    HTTPField("transfer-encoding: ", "", "H"),
                     HTTPField("upgrade: ", "", "H"),
                    HTTPField("via: ", "", "H"),
                     HTTPField("warning: ", "", "H"),
                    HTTPField("accept-ranges: ", "", "H"),
                     HTTPField("age: ", "", "H"),
                    HTTPField("etag: ", "", "H"),
                     HTTPField("location: ", "", "H"),
                    HTTPField("proxy-authenticate: ", "", "H"),
                     HTTPField("retry-after: ", "", "H"),
                    HTTPField("server: ", "", "H"),
                     HTTPField("vary: ", "", "H"),
                    HTTPField("allow: ", "", "H"),
                     HTTPField("content-encoding: ", "", "H"),
                    HTTPField("content-language: ", "", "H"),
                     HTTPField("content-length: ", "", "H"),
                    HTTPField("content-disposition: ", "", "H"),
                     HTTPField("strict-transport-security: ", "", "H"),
                    HTTPField("www-authenticate: ", "", "H"),
                     HTTPField("x-frame-options: ", "", "H"),
                    HTTPField("x-xss-protection: ", "", "H"),
                     HTTPField("x-powered-by: ", "", "H"),
                     HTTPField("content-security-policy: ", "", "H"),
                     HTTPField("x-content-security-policy: ", "", "H"),
                     HTTPField("x-webkit-csp: ", "", "H"),
                     HTTPField("x-ua-compatible: ", "", "H"),
                     HTTPField("x-content-type-options: ", "", "H"),
                     HTTPField("x-ua-compatible: ", "", "H"),
                    HTTPField("refresh: ", "", "H"),
                     HTTPField("content-md5: ", "", "H"),
                    HTTPField("content-range: ", "", "H"),
                     HTTPField("content-type: ", "", "H"),
                    HTTPField("expires: ", "", "H"),
                     HTTPField("last-modified: ", "", "H"),
                    HTTPField("extension-header: ", "", "H"),
                     HTTPField("link: ", "", "H"),
                    HTTPField("mime-version: ", "", "H"),
                     HTTPField("retry-after: ", "", "H"),
                    HTTPField("title: ", "", "H"),
                     HTTPField("uri: ", "", "H"),
                    HTTPField("public: ", "", "H"),
                     HTTPField("accept-patch: ", "", "H"),
                    HTTPField("cookie: ", "", "H"),
                     HTTPField("set-cookie: ", "", "H"),
                    #HTTPField("x-forwarded-for: ", "", "H"), X-Forwarded for is not a response header, it's a request
                     HTTPField("keep-alive: ", "", "H"),
                    HTTPField("unknown-header(s): ", "", "H"),
                     HTTPMsgField("message-body: ", "")]


bind_layers(TCP, HTTPResponse, sport=80)
bind_layers(TCP, HTTPRequest, dport=80)
