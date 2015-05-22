from multiprocessing import Process, Queue
import scapy.all as scapy
import scapy.modules.p0f as p0f
import time
import socket
import logger

class p0f_sniffer:

        def __init__(self, options, database):
                self.options = options
                self.database = database
                self.proc = Process(target=self.sniff)
                self.logger = logger.logger(self)

        def start(self):
                self.proc.start()

        def stop(self):
                self.proc.join()

        def sniff(self):
                # Start Scapy sniffer on interface
                try:
                        scapy.sniff(iface = self.options.listen_interface, prn = self.update_os_info, filter = self.options.p0f_filter, store = 0)
                except socket.error, e:
                        self.logger.error("P0f sniffer error on %s: %s" % (self.options.listen_interface, e[1]))

        def update_os_info(self, pkt):

                if not 'TCP' in pkt:
                        return

                tos = self.get_os_info(pkt)
                if tos:
                        ip = pkt.sprintf("%IP.src%")
                        os = tos[0]
                        os_ver = tos[1]
                        distance = tos[2]
                        uptime = self.get_uptime_info(pkt)
                        self.database.push("INSERT INTO ips(ip_addr, ip_os, ip_os_ver, ip_uptime, ip_distance) VALUES (INET_ATON('%s'), '%s', '%s','%d','%d') ON DUPLICATE KEY UPDATE ip_os = '%s', ip_os_ver = '%s', ip_uptime = '%d', ip_distance = '%d'" % (ip, self.database.escape(os), self.database.escape(os_ver), int(uptime), int(distance), self.database.escape(os), self.database.escape(os_ver), int(uptime), int(distance)))

        # Determine packet OS through p0f
        def get_os_info(self, pkt):
                tcpflags = pkt.sprintf("{TCP:%TCP.flags%}")
                if 'S' in tcpflags and not ('A' in tcpflags or 'R' in tcpflags or 'F' in tcpflags):
                        try:
                                p0f_list = p0f.p0f(pkt)
                                if len(p0f_list) > 0:
                                        return p0f_list[0]
                        except:
                                pass

                return False

        def get_uptime_info(self, pkt):
                for opt in pkt.options:
                        if opt[0] == "Timestamp":
                                t = opt[1][0] / 100
                                return t
                return False
