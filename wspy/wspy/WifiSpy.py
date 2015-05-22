import time

from scapy.all import sniff, Dot11
import wireless

class WifiHeaderPacketsParser(object):
    # This value handles when to remove a client from the network
    TIMES = 15
    
    def __init__(self):
        self.clients = {}
        self.actions = []
        
    def reset(self):
        self.clients = {}
        self.actions = []
       
    def feed(self, packets, ap):
        for pkt in packets:
            header = pkt.getlayer(Dot11)
            
            # Management type
            if header.type == 0:
                # Assoc request-response | Reassoc request-response
                if (header.subtype >= 0 and header.subtype <= 3) and\
                    (str(header.addr1).upper() == ap or\
                     str(header.addr2).upper() == ap or\
                     str(header.addr3).upper() == ap):
                        self.__add_action(header)
                if (header.subtype == 4):
                    if (header.addr1 == 'ff:ff:ff:ff:ff:ff' or str(header.addr1).upper() == ap):
                        self.__add_action(header)
                if (header.subtype == 5 and str(header.addr2) == ap):
                    self.__add_action(header)
                if (header.subtype == 10 and str(header.addr2) == ap):
                    self.__add_action(header)
                if (header.subtype == 11 and str(header.addr1) == ap):
                    self.__add_action(header)
                if (header.subtype == 12 and str(header.addr2) == ap):
                    self.__add_action(header)
                    
            # Control packets
            if header.type == 1 and header.subtype == 10 \
                and str(header.addr1).upper() == ap:
                    addr = str(header.addr2).upper()
                    self.clients[addr] = self.TIMES
            
            # Data packets
            if header.type == 2 and (str(header.addr1).upper() == ap or
                                     str(header.addr2).upper() == ap or
                                     str(header.addr3).upper() == ap):
                
                if (header.FCfield & 1 and not (header.FCfield & 2)):
                    addr = str(header.addr2).upper()
                    self.clients[addr] = self.TIMES
                
                # Check if is a From DS
                elif (header.FCfield & 2 and not (header.FCfield & 1)):
                    addr = str(header.addr1).upper()
                    if addr == 'FF:FF:FF:FF:FF:FF':
                        addr = str(header.addr3).upper()
                        self.clients[addr] = self.TIMES
        
        self.__update_clients()                
        
    def __update_clients(self):
        # Update clients
        temp_list = []
        for i in self.clients.iterkeys():
            self.clients[i] -= 1
            if self.clients[i] == 0:
                temp_list.append(i)
                    
        for i in temp_list:
            del self.clients[i]
                        
    def __add_action(self, header):
        if header.subtype == 0:
            self.actions.append(("Association request", header.addr2.upper()))
        elif header.subtype == 1:
            self.actions.append(("Association response", header.addr1.upper()))
        elif header.subtype == 2:
            self.actions.append(("Reassociation request", header.addr2.upper()))
        elif header.subtype == 3:
            self.actions.append(("Reassociation response", header.addr1.upper()))
        elif header.subtype == 4:
            self.actions.append(("Probe request", header.addr2.upper()))
        elif header.subtype == 5:
            self.actions.append(("Probe response", header.addr1.upper()))
        elif header.subtype == 10:
            self.actions.append(("Disassociation", header.addr2.upper()))
        elif header.subtype == 11:
            self.actions.append(("Authentication", header.addr1.upper()))
        elif header.subtype == 12:
            self.actions.append(("Deauthentication", header.addr2.upper()))
         
class WifiSpyError(Exception):
    pass        

class WifiSpy(object):
    def __init__(self, iface):
        # For scanning
        self.level = "medium" # low, medium, high
        self.__results = []
        
        # To get packages
        self.channel = -1
        self.ap = None
        self.is_in_monitor_mode = False
        
        # To parse header packets
        self.parser = WifiHeaderPacketsParser()
        
        # Wireless interface handler
        try:
            self.__iface = wireless.Wireless(iface)
        except wireless.error:
            raise WifiSpyError("Provided interface must have wireless \
                                extensions")
        
    def set_iface_in_monitor_mode(self):
        if self.channel < 1 or self.channel > 13:
            raise WifiSpyError("Valid channel must be provided before putting \
                                the interface in monitor mode")
        
        if self.__iface.is_in_monitor_mode():
            self.parser.reset()
            self.__iface.set_channel(self.channel)
            self.is_in_monitor_mode = True
            return
        
        if self.__iface.is_up():
            self.__iface.set_iface_down()
            
        if not self.__iface.set_mode("Monitor") or \
           not self.__iface.set_iface_up():
            raise WifiSpyError("Interface cannot be put in monitor mode")
        
        self.parser.reset()
        self.__iface.set_channel(self.channel)
        self.is_in_monitor_mode = True
        
    def set_iface_in_managed_mode(self):
        if self.__iface.is_in_managed_mode():
            return
        
        if self.__iface.is_up():
            self.__iface.set_iface_down()
            
        if not self.__iface.set_mode("Managed") or \
           not self.__iface.set_iface_up():
            raise WifiSpyError("Interface cannot be put in managed mode")
        
    def __get_packages_from_network(self):
        """ 
        This function will return a list of packages from the specified network.
        The list can be empty.
        """
        if not self.is_in_monitor_mode:
            raise WifiSpyError("Interface must be put in monitor mode before \
                                getting a package")
        if self.ap == None:
            raise WifiSpyError("Ap must be set before getting a package")
        
        list = []
        time = 0.5
        
        # How many times do we have to try?
        if self.level == "high": time = 4 * time
        elif self.level == "medium": time = 3 * time
        else: time = 2 * time
        
        return sniff(iface=self.__iface.get_iface_name(), \
                lfilter = lambda x: x.haslayer(Dot11), timeout=time)
    
    def update(self):
        packets = self.__get_packages_from_network()
        self.parser.feed(packets, self.ap)
        
    def get_clients_from_network(self):
        return self.parser.clients.keys()
    
    def get_actions_from_network(self):
        return self.parser.actions
        
    def get_scanning_results(self):
        """
        This function returns a list of dictionaries containing the data
        of the scanned networks succesive calls will update the results
        adding new networks.
        """
        
        if self.level == "high": iterations = 4
        elif self.level == "medium": iterations = 3
        else: iterations = 2
        
        updated = False
        
        for _ in xrange(iterations):
            if not len(self.__results):
                self.__results = self.__iface.scan()
                updated = True
            else:
                essids = [x["Essid"] for x in self.__results]
                for i in self.__iface.scan():
                    if (i["Essid"] not in essids):
                        self.__results.append(i)
                        updated = True
                     
            # If no new networks found return   
            if not updated:
                break
            
            time.sleep(0.3)
            
        return self.__results