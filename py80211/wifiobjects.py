import time
import liboui2

def pformatMac(hexbytes,delimiter):
    """
    Take in hex bytes and pretty format them
    to the screen in the xx:xx:xx:xx:xx:xx format
    """
    mac = []
    if hexbytes is not None:
        for byte in hexbytes:
            mac.append(byte.encode('hex'))
        return delimiter.join(mac).upper()
    else:
        return hexbytes

class ess:
    """
    extended service area object
    """
    def __init__(self):
        self.fts = time.time()      # first time object is seen
        self.lts = None             # last time object is seen, update on every acccess
        self.name = "ess"           # object type
        self.points = []            # list of bssids that belong to ess

class accessPoint:
    """
    Access point object
    """
    def __init__(self, bssid):
        # set first time seen
        self.fts = time.time()      # first time object is seen
        self.lts = None             # last time object is seen, update on every acccess
        self.name = "accessPoint"   # object type
        self.hostname = None        # device hostname as reported by AP (not all vendors support)
        self.connectedClients = []  # list of connected clients
        self.essid = None           # broadcasted essid
        self.bssid = bssid          # bssid of ap
        self.hidden = False         # denote if essid is hidden
        self.encryption = None      # show encryption level
        self.auth = None            # show authentication settings
        self.cipher = None          # cipher, either CCMP, TKIP, wep 64/128
        self.wps = False            # WPS support, its True/False
        self.channel = None         # ap's channel
        self.ssidList = []          # rolling list of seen ssid's for this ap
        self.oui = self.populateOUI() # lookup the object oui
        self.rssi = None            # current rssi
        self.rates = []             # list of supported rates
        self.htPresent = False      # HT IE tags Indicates 802.11AC/N support
        self.country = None         # Country Code
        self.band = []              # list of bands, a, ab, abg, ac, n
        self.reportedclients = 0    # number of clients AP reports to have
        self.fiveghzChannels = (36, 38,
            40, 42, 44, 46, 52, 56,
            58, 60, 100, 104, 108, 112,
            116, 120, 124, 128, 132, 136,
            140, 149, 153, 157, 161, 165) # 5ghz channel list
        self.twofourghzChannels = range(1, 15) # 2.4ghz channel list
        self.bcast = False          # used for airdrop, bcast kick packets are not allowed by default
        self._pcounter = 0

    def update_packet_counter(self):
        """
        update the number of packets we have seen for a given AP
        """
        self._pcounter += 1

    def get_packet_counter(self):
        """
        Return the packet counter
        """
        return self._pcounter

    def updaterates(self, rates):
        """
        add rates / extended rates
        """
        if type(rates) is list:
            self.rates.extend(rates)
        else:
            self.rates.append(rates)
        # sort rates so they are in order
        # ulgy hack to ensure uniqueness
        runique = {}
        for i in self.rates:
            runique[i] = ""
        self.rates = runique.keys()
        self.rates.sort()

    def getband(self):
        """
        return if its an ABGN AC network
        """
        band = []
        if len(self.rates) == 0:
            return "Unknown"
        if 11 in self.rates:
            band.append('B')
        if 54 in self.rates and self.channel in self.fiveghzChannels:
            band.append('A')
        elif 54 in self.rates and self.channel in self.twofourghzChannels:
            band.append('G')
        if self.htPresent is True:
            band.append('N')
        # implment AC here
        self.band = band
        return "/".join(self.band)

    def populateOUI(self):
        """
        populate the OUI vars for the object
        uses liboui2
        """
        myoui = liboui2.Oui('oui.txt')
        return myoui.search(pformatMac(self.bssid[:3],':'), "m")

    def addClients(self, client):
        """
        update connected clients and ensure they are unique
        """
        try:
            self.connectedClients.index(client)
        except ValueError:
            self.connectedClients.append(client)
    
    def delClients(self, client):
        """
        remove a client from connectedClients list
        """
        try:
            self.connectedClients.remove(client)
            # it worked to return 0
            return 0
        except ValueError:
            # it failed return -1
            return -1

    def numClients(self):
        """
        return number of connected clients
        as an tuple, number we see, reported by cisco ap's
        """
        return (len(self.connectedClients), self.reportedclients)
    
    def updateEssid(self, essid, iternum=3):
        """
        help prevent mangled ssids from being set
        require us to see it at least 3 times before we update
        as new ssids come in old ones get phased out
        essid = essid in hex
        iternum = int num of ssids to compair agasint
        """
        counter = 0
        if len(self.ssidList) < iternum:
            # havent seen 3 beacons yet, set first essid we see
            self.essid = essid
        for ssid in self.ssidList:
            if essid != ssid:
                # something didnt match stop checking
                break
            if essid == ssid and counter == iternum:
                # all 3 matched, update
                self.essid = essid
            counter += 1
        # remove first record and append new one to back
        if len(self.ssidList) != 0:
            self.ssidList.pop(0)
        self.ssidList.append(essid)
            
class client:
    """
    Client object
    """
    def __init__(self, mac):
        """
        mac = client mac address in hex
        """
        self.fts = time.time()        # first time object is seen
        self.lts = None               # last time object is seen, update on every access 
        self.name = "client"          # object type
        self.mac = mac                # client mac address
        self.probes = []              # list of probe requests client broadcast
        self.assoicated = False       # list if client is associated to an ap
        self.bssid = None             # Bssid of assoicated ap
        self.wired = False            # not a wired client by default
        self.lastBssid = None         # last connected bssid
        self.managedFrame = False     # have we seen a managment frame from this client?
        self.oui = self.populateOUI() # populate clients oui lookup
        self.rssi = None              # client rssi
        self.apObject = None          # stores reference link to ap object when connected to bssid
        self._pcounter = 0

    def update_packet_counter(self):
        """
        update the number of packets we have seen for a given client device
        """
        self._pcounter += 1

    def get_packet_counter(self):
        """
        Return the packet counter
        """
        return self._pcounter

    def populateOUI(self):
        """
        populate the OUI vars for the object
        uses liboui2
        """
        myoui = liboui2.Oui('oui.txt')
        return myoui.search(pformatMac(self.mac[:3],":"), "m")

    def updateProbes(self, probe):
        """
        update probes list and keep it unique
        """
        try:
            self.probes.index(probe)
        except ValueError:
            self.probes.append(probe)
            
    def numProbes(self):
        """
        return number of probe requests
        as an int
        """
        return len(self.probes)
    
    def getEssid(self):
        """
        return essid of current assoication
        """
        if self.apObject is not None:
            if self.apObject.essid is None:
                return "<Hidden Essid>"
            else:
                return self.apObject.essid.encode('utf-8')
        else:
            return "Not Assoicated"

    def updateBssid(self, bssid):
        """
        update last connected and
        current connected bssids
        """
        self.lastBssid = self.bssid
        self.bssid = bssid

    def updateWired(self, state):
        """
        prevent a wireless client from being marked wired
        """
        if self.managedFrame is not True:
            self.wired = state
