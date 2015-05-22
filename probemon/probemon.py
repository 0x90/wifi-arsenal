import PyLorcon2 as pylorcon
import time

class ProbeMonitor:
	iface = "wlan0"
	vap = iface
	driver = 'mac80211'
	mac = (0, 2, 114, 105, 40, 255)
	channel = 1
	timeout = 123
	data = "\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x21\x21" \
		"\x21\x21\x21\x00\x21\x21\x21\x21\x21\x90\x83\x50\x8c" \
		"\xf4\x38\x23\x00\x00\x00\x64\x00\x11\x04\x00\x06BEACON" \
		"\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x01" \
		"\x32\x04\x0c\x12\x18\x60"

	def setup(self):
		self.ctx = pylorcon.Context(self.iface)
		self.ctx.open_injmon()
		print "Set up context and set to monitor/injection mode."	
	def test(self):
		self.ctx.send_bytes(self.data)
		print "[*] Becon packet emitted."	

if __name__ == "__main__":
	pm = ProbeMonitor()
	pm.setup()
	while(1):
		pm.test()
		# 0.2secs per beacon appears to make the other
		# wireless cards/adapters pick them up
		time.sleep(0.2)


