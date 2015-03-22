#!/usr/bin/env python

try:
	from scapy.all import *
	from Tkinter import *
	import os
	from iface_list import GetInterfaceList
	from scanner import WifiScanner, ThreadedClient
	from sniffer import ThreadSniffer
	import tkMessageBox
except ImportError, e:
	pass

class SetInterface:
	def __init__(self):
		# declaring wireless interface as empty
		if "interface" not in globals():
			# Creating a window displaying available wireless interfaces
			self.iface_win = Toplevel()
			self.iface_win.title("Enter interface")
			container = Frame(self.iface_win, highlightbackground="black", highlightthickness=2)
			title = Label(container, text="Choose your preferred \nwireless interface:\n", font="Verdana 12 bold").pack()
			self.box = Frame(container, highlightbackground="black", highlightthickness=2)
			self.var = StringVar()
			
			# Getting list of available wireless interfaces and their mode of operation from GetInterfaceList class in iface_list.py.
			self.interfaces = GetInterfaceList().getIface()
			list_interfaces = self.choose_interface()
			#Label(self.box, text="Interface: ").pack(side=LEFT, padx=5, pady=10)
			#self.v = StringVar()
			#self.e = Entry(self.box, width=40, textvariable=self.v).pack(side=LEFT)
			self.box.pack()
			submit_btn = Button(container, text="Scan", command=self.callback).pack()
			container.pack(ipadx=10, ipady=10, expand=YES, fill=BOTH)
			self.iface_win.mainloop()
		else:
			pass
		
	def choose_interface(self):
		count = 0
		for iface, mode in self.interfaces:
			count += 1
			text = str(count) + ". " + iface + " (Mode: %s)" %mode
			Radiobutton(self.box, text=text, value=str(iface+":"+mode), variable=self.var, font="Verdana 13 bold").pack(ipadx=5)
			
	def TurnMonitorOn(self, iface):
		os.system("sudo ifconfig %s down" % iface)
		os.system("sudo iwconfig %s mode monitor" % iface)
		os.system("sudo ifconfig %s up" % iface)
		
	def callback(self):
		try:
			self.var.get()
		except NameError, IndexError:
			print "Error"
		else:
			chosed_iface_mode = self.var.get()
			iface_mode = chosed_iface_mode.split(':')
			iface = iface_mode[0]
			mode = iface_mode[1]
			global interface
			interface = iface
			if mode == "managed":
				ask_user = tkMessageBox.askokcancel(title="Turn on Monitor mode", message="Monitor Mode isn't yet enabled on this interface. Turn on Monitor mode on %s interface?"%iface)
				if ask_user > 0 :
					self.TurnMonitorOn(iface)
			self.iface_win.destroy()
		return

# for Scan > Access Points

def scan_ap(iface, canvas):
	if iface == "":
		import gui.container
		iface = gui.container.interface
	else: iface = iface
	table = Toplevel()
    	table.title("Wireless Scanning: Access Points")
    	scan = ThreadedClient()
    	scan.main(table, iface, canvas, "AP")
    	table.mainloop()
	
def scan_client(iface):
	if iface == "":
		import gui.container
		iface = gui.container.interface
		canvas = gui.container.canvas
	else: iface = iface
	table = Toplevel()
    	table.title("Wireless Scanning: Stations")
    	scan = ThreadedClient()
    	scan.main(table, iface, canvas, "Client")
    	table.mainloop()

def scan_all(iface):
	if iface == "":
		import gui.container
		iface = gui.container.interface
	else: iface = iface
	table = Toplevel()
    	table.title("Wireless Scanning")
    	scan = ThreadedClient()
    	scan.main(table, iface, "", "position")
    	table.mainloop()
    	
def stop_sniffer():
	sniff_obj = ThreadSniffer()
	sniff_obj.endApplication()
#def sniffall(iface, container):
	#sniff = ThreadSniffer(container, iface)
	
def read_documentation(event):
	print "Print Documentation"
	
