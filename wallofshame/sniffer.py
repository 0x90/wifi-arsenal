from multiprocessing import Process, Queue
import scapy.all as scapy
import time
import socket
import logger

class packet:
        def __init__(self):
                self.src = None
                self.dst = None
                self.data = ''
                self.os = None

class stream(list):
        def __init__(self, shash, src, dst):
                self.shash = shash
                self.src = src
                self.dst = dst
                self.data = ''
                self.finished = False
                list.__init__(self)

        def addpkt(self, pkt):
                if self.finished:
                        return

                self.append(pkt)
                if len(self) > 1 and (self[-2]['TCP'].seq%(2**32) > self[-1]['TCP'].seq%(2**32)):
                        self.sort(cmp = self.sortfunc)

                self.last_pkt_time = time.time()


        def sortfunc(self, a, b):
                return cmp(a['TCP'].seq%(2**32), b['TCP'].seq%(2**32))

        def concat(self, accum, pkt):
                if 'Raw' not in pkt:
                        return accum
                
                accum += str(pkt['Raw'])

                if pkt['TCP'].dport == 80:
                        accum += "\r\n\r\n"

                return accum

        def finish(self):
                self.finished = True
                self.data = reduce(self.concat, self, "")

class sniffer:

        def __init__(self, options, parser, database):
                self.options = options
                self.parser = parser
                self.database = database
                self.streams = {}
                self.proc = Process(target=self.sniff)
                self.logger = logger.logger(self)
                self.last_gc_check = 0

        def start(self):
                self.proc.start()

        def stop(self):
                self.proc.join()

        def sniff(self):
                if self.options.pcap_file == 'None':
                        self.logger.info("Using network interface: %s" % (self.options.listen_interface))
                        try:
                                scapy.sniff(iface = self.options.listen_interface, prn = self.pkt_callback, lfilter = self.pkt_check, filter = self.options.filter, store = 0)
                        except socket.error, e:
                                self.logger.error("Sniffer error on %s: %s" % (self.options.listen_interface, e))
                else:
                        self.logger.info("Using pcap file: %s" % (self.options.pcap_file))
                        pcapr = scapy.PcapReader(self.options.pcap_file)
                        while 1:
                                try:
                                    pkt = pcapr.next()
                                    if self.pkt_check(pkt):
                                        self.pkt_callback(pkt)
                                except scapy.StopIteration, e:
                                    break

        def pkt_is_last(self, pkt):
                if pkt['TCP'].flags == 17 or pkt['TCP'].flags == 25:
                        return True
                return False

        def pkt_hash(self, pkt):
                sdip = (pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport)
                return (sdip)

        def pkt_check(self, pkt):
		#print "Check packet callback called"
                #if pkt.haslayer('Dot11'):
		#	print "Layer Dot11 detected"
                # TODO: useful wifi information here
                if ('IP' not in pkt) or ('TCP' not in pkt):
		#	print "Check packet return false"
                        return False
		#print "Check packet return true"
                return True

        def pkt_callback(self, pkt):
		#print "Packet callback called"
                tnow = time.time()
                if (tnow - self.last_gc_check) > self.options.tcp_assemble_timeout:
                        self.stream_gc(tnow)

                shash = self.pkt_hash(pkt)

                if shash not in self.streams:
                        src = (pkt['IP'].src, pkt['TCP'].sport) 
                        dst = (pkt['IP'].dst, pkt['TCP'].dport) 
                        self.streams[shash] = stream(shash, src, dst)
                
                self.streams[shash].addpkt(pkt)

                if self.pkt_is_last(pkt):
                         self.streams[shash].finish()
                         self.stream_to_parser(self.streams[shash])
                         del self.streams[shash]

        def stream_gc(self, tnow):
                rmv = []
                for shash in self.streams:
                        if (not self.streams[shash].finished) and ((tnow - self.streams[shash].last_pkt_time) > self.options.tcp_assemble_timeout):
                                rmv.append(shash)
                for shash in rmv:
                        self.streams[shash].finish()
                        self.stream_to_parser(self.streams[shash])
                        del self.streams[shash]

        def stream_to_parser(self, stream):
                pkt = packet()
                pkt.src = stream.src
                pkt.dst = stream.dst
                pkt.data = stream.data
                self.parser.push(pkt)
                del pkt
