import pcapy
import dpkt, socket
import calendar, time
import datetime
import os
from decimal import Decimal
from subprocess import Popen
from optparse import OptionParser
import signal
import sys

class PcapFileWriter:
	def __init__(self, pc, maxSecondsInterval, fileSizeLimitMB, filenamesuffix, remotehost, remotepath, remoteuser):
		self.currentFile = None
		self.pc = pc
		self.maxSecondsInterval = int(maxSecondsInterval)
		self.filesize_check_time = 0
		self.fileSizeLimit = int(fileSizeLimitMB) * 1000000;
		self.filenamesuffix = filenamesuffix
		self.projectPath = os.path.dirname(os.path.abspath(__file__))
		self.remotehost = remotehost
		self.remoteuser = remoteuser
		self.remotepath = remotepath

	def get_current_file(self):
		if self.currentFile is None:
			self.create_new_file()
			print "new file created"
		if self.isFileTooBig() or self.has_time_limit_passed():
			# save old current file?
			self.backupPcapFile(self.current_file_timestamp, self.getPcapFilePathAndName())
			self.create_new_file()
			print "old file saved. new file created"

		return self.currentFile

	def create_pcap_filename(self):
		if self.filenamesuffix:
			self.currentFileName = str(self.current_file_timestamp) + "_" + self.filenamesuffix.replace(" ", "-") + ".pcap"
		else:
			self.currentFileName = str(self.current_file_timestamp) + ".pcap"
		return self.currentFileName

	def create_pcap_filepath(self):
		 self.currentFilepath = self.projectPath + "/pcaps"
		 if os.path.exists(self.currentFilepath)is False:
		 	os.mkdir(self.currentFilepath)
		 return self.currentFilepath

	def getPcapFilePathAndName(self):
		return self.currentFilepath + "/" + self.currentFileName

	def get_time(self):
		return calendar.timegm(time.gmtime())

	def isFileTooBig(self):
		# Only check every 30 seconds
		if self.get_time() < self.filesize_check_time + 30:
			return False
		else:
			filesize = os.path.getsize(self.getPcapFilePathAndName())
			print filesize
			self.filesize_check_time = self.get_time()
			if filesize >= self.fileSizeLimit:
				return True
			else:
				return False

	def has_time_limit_passed(self):
		timeLimit = self.current_file_timestamp + self.maxSecondsInterval
		if self.get_time() >= timeLimit:
			return True
		else:
			return False

	def create_new_file(self):
		self.current_file_timestamp = self.get_time()
		self.create_pcap_filename()
		self.create_pcap_filepath()
		self.currentFile = dpkt.pcap.Writer(open(self.getPcapFilePathAndName(),'wb'))

	def writeToFile(self, ts, data):
		self.get_current_file()
		self.currentFile.writepkt(data, ts)
		return self.getPcapFilePathAndName()

	def backupPcapFile(self, timestamp, filepath):
		dateStr = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
		movescriptPath = self.projectPath + '/movescript.sh'
		p = Popen(['bash', movescriptPath, dateStr, filepath, self.remoteuser, self.remotehost, self.remotepath])

def get_packet_metadata(pkt, ts):
    eth = dpkt.ethernet.Ethernet(pkt)
    metadata = {}
    metadata['timestamp'] = ts
    metadata['src'] = mac_addr(eth.src)
    metadata['dst'] = mac_addr(eth.dst)
    try:
        ip = eth.data
        tcp = ip.data
        try:
            metadata['ip'] = {}
            metadata['ip']['src'] = socket.inet_ntoa(ip.src)
            metadata['ip']['dst'] = socket.inet_ntoa(ip.dst)
            if tcp.dport == 80 and len(tcp.data) > 0:
                try:
                    http = dpkt.http.Request(tcp.data)
                    metadata['http'] = {}
                    metadata['http']['headers'] = http.headers
                except TypeError as e:
                    pass
        except:
            pass
    except:
        pass
    return metadata

def main():
	global options
	global args
	global pcapWriter
	global pc
	# parse command line arguments
	parser = OptionParser()
	parser.add_option("-i", "--interface", dest="interface", help="network interface to listen on")
	parser.add_option("-s", "--filesizelimit", dest="filesizelimit", help="Maximum pcap filesize, in MB")
	parser.add_option("-t", "--maxseconds", dest="maxsecondsinterval", help="Maximum duration for a pcap file to cover, in seconds.")
	parser.add_option("-f", "--filenamesuffix", dest="filenamesuffix", help="Suffix to add after timestamp in filename.")
	parser.add_option("-r", "--remotehost", dest="remotehost", help="Remote host to backup pcaps")
	parser.add_option("-u", "--remoteuser", dest="remoteuser", help="Remote username to backup pcaps")
	parser.add_option("-p", "--remotepath", dest="remotepath", help="Path on remote host to backup to")
	(options, args) = parser.parse_args()
	
	# list all the network devices
	pcapy.findalldevs()

	max_bytes = 1500
	promiscuous = True
	read_timeout = 100

	pc = pcapy.open_live(options.interface, max_bytes, promiscuous, read_timeout)
	pcapWriter = PcapFileWriter(pc, options.maxsecondsinterval, options.filesizelimit, options.filenamesuffix, options.remotehost, options.remotepath, options.remoteuser)

	packet_limit = -1
	pc.loop(packet_limit, process_packets)

def process_packets(header, data):
	global pcapWriter
	ts = Decimal('{0}.{1}'.format(*header.getts()))
	metadata = get_packet_metadata(data, ts)
	filepath = pcapWriter.writeToFile(ts, data)
	#print "%d: %s ==> %s." % (metadata['timestamp'], metadata['src'], metadata['dst'])

def mac_addr(mac_string):
    return ':'.join('%02x' % ord(b) for b in mac_string)

def checkOrMakeDir(path = "", dirName = ""):
	if not os.path.exists(path + dirName):
		os.makedirs(path + dirName)

def signal_handler(signal, frame):
	global pcapWriter
	global pc
	print('SIGINT received. Backing up current file.')
	pcapWriter.backupPcapFile(pcapWriter.current_file_timestamp, pcapWriter.getPcapFilePathAndName())
	exit(0);

signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    main()