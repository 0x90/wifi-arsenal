from scapy.all import Dot11ProbeReq, Dot11Elt
import re
import logging

def prefilter(p):
    #Sometimes tcpdump returns garbled probe-request data. This is
    # a dirty hack to try and detect those cases
    if p.haslayer(Dot11ProbeReq):
        if not re.match("[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]", p.addr2):
            logging.debug("Bad MAC address detected: %s" % p.addr2)
            return False
        else:
            if p[Dot11Elt].info != '':
                ssid = p[Dot11Elt].info
                try:
                    ssid = ssid.decode('utf-8')
                except:
                    logging.debug("Bad SSID detected: %s" % ssid)
                    return False
                if len(ssid) == 0:
                    return False

    return True #Default operation
