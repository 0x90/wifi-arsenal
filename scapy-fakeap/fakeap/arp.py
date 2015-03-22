import threading
from rpyutils import printd, Level


class ARPHandler():
    def __init__(self):
        self.mutex = threading.Lock()
        self.arp_table = {}

    def add_entry(self, client_ip, client_mac):
        self.mutex.acquire()
        if client_ip not in self.arp_table:
            self.arp_table[client_ip] = client_mac
        self.mutex.release()

    def get_entry(self, client_ip):
        self.mutex.acquire()
        try:
            temp = self.arp_table[client_ip]
        except KeyError:
            temp = None
            printd("Could not find IP %s in ARP table." % client_ip, Level.WARNING)
        self.mutex.release()

        return temp
