#!/usr/bin/env python
import time
import urllib2 as ul
import socket as sckt
from wpp.config import termtxtcolors as colors

def getIP(ifname='eth0'):
    """
    return: ips: {'ifname':'ipaddr'}
    """
    use_netifs = False
    try:
        import netifaces as nifs
        use_netifs = True
    except ImportError:
        #pass
        import fcntl
        import struct
    if not use_netifs:
        s = sckt.socket(sckt.AF_INET, sckt.SOCK_DGRAM)
        addr = sckt.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, # SIOCGIFADDR
                                struct.pack('256s', ifname[:15]) )[20:24])
        ips = {ifname: addr}
    else:
        ips = {}
        inet_id = nifs.AF_INET
        ifaces = nifs.interfaces()
        ifaces.remove('lo')
        for iface in ifaces:
            ifaddrs = nifs.ifaddresses(iface)
            if inet_id in ifaddrs:
                inets = ifaddrs[inet_id]
                if len(inets) == 1: ips[iface] = inets[0]['addr']
                else:
                    for idx,inet in enumerate(inets):
                      ips[iface] = {}
                      ips[iface][idx] = inet['addr']
    return ips


def sendMail(sender, userpwd, recipient, subject, body):
    """Send an email.
    All arguments should be Unicode strings (plain ASCII works as well).
    Only the real name part of sender and recipient addresses may contain
    non-ASCII characters.
    The email will be properly MIME encoded and delivered though SMTP to
    localhost port 25.  This is easy to change if you want something different.
    The charset of the email will be the first one out of US-ASCII, ISO-8859-1
    and UTF-8 that can represent all the characters occurring in the email.
    """
    from smtplib import SMTP
    from email.MIMEText import MIMEText
    from email.Header import Header
    from email.Utils import parseaddr, formataddr
    # Header class is smart enough to try US-ASCII, then the charset we
    # provide, then fall back to UTF-8.
    header_charset = 'ISO-8859-1'
    # We must choose the body charset manually
    for body_charset in 'UTF-8', 'US-ASCII', 'ISO-8859-1':
        try:
            body.encode(body_charset)
        except UnicodeError: pass
        else: break
    # Split real name (which is optional) and email address parts
    sender_name, sender_addr = parseaddr(sender)
    recipient_name, recipient_addr = parseaddr(recipient)
    # We must always pass Unicode strings to Header, otherwise it will
    # use RFC 2047 encoding even on plain ASCII strings.
    sender_name = str(Header(unicode(sender_name), header_charset))
    recipient_name = str(Header(unicode(recipient_name), header_charset))
    # Make sure email addresses do not contain non-ASCII characters
    sender_addr = sender_addr.encode('ascii')
    recipient_addr = recipient_addr.encode('ascii')
    # Create the message ('plain' stands for Content-Type: text/plain)
    msg = MIMEText(body.encode(body_charset), 'plain', body_charset)
    msg['From'] = formataddr((sender_name, sender_addr))
    msg['To'] = formataddr((recipient_name, recipient_addr))
    msg['Subject'] = Header(unicode(subject), header_charset)
    # Send the message via SMTP to localhost:25
    smtp = SMTP("smtp.gmail.com:587")
    smtp.starttls()  
    smtp.login(userpwd[0], userpwd[1])  
    smtp.sendmail(sender, recipient, msg.as_string())
    smtp.quit()


def setProxy():
    proxyserver = "http://proxy.cmcc:8080"
    proxy = {'http': proxyserver}
    #sckt.setdefaulttimeout(50)
    opener = ul.build_opener( ul.ProxyHandler(proxy) )
    ul.install_opener( opener )


def connectRetry(**ka):
    """ try 5 times at most. """
    def decorator(f, **kb):
        def wrapper(*args, **kc):
            delay = 1; result = None
            if 'try_times' in ka and type(ka['try_times']) is int: 
                try_times = ka['try_times']
            else: 
                try_times = 5
            if 'timeout' in ka and type(ka['timeout']) is int: 
                timeout = ka['timeout']
            else: 
                timeout = 5
            for i in xrange(try_times):
                try:
                    sckt.setdefaulttimeout(timeout)
                    result = f(*args, **kc)
                    break
                except (sckt.error, ul.URLError), e:
                    if hasattr(e, 'code'):
                        print(colors['red'] % ('HTTP Error: (%s): %s' % (e.code, e.msg)))
                    elif hasattr(e, 'reason'):
                        print(colors['red'] % ('URL Error: %s!' % e.reason))
                    else: print e
                except Exception, e: print e
                delay += 0.5; time.sleep(delay)
                print colors['blue'] % '... Retrying ...'
            return result
        return wrapper
    return decorator
