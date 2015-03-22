class arpObject:
    """
    object to store wifi client arp info in
    """
    def __init__(self, clientMac, bssid, ipaddr):
        self.clientMac = clientMac
        self.bssid = bssid
        self.ipaddr = ipaddr
