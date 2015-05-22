#!/usr/bin/env python

try:
	from Tkinter import *
	import tkMessageBox
	import Pmw
	from random import randint
	from wireless.menu_functions import *
	from wireless.iface_list import ListInterfaces, GetInterfaceList
	
except ImportError, e:
	pass

class DisplayBox:
	def __init__(self, parent):
		self.myParent = parent
		Pmw.initialise()
		self.balloon = Pmw.Balloon(parent)
		
		# Color declaration
		self.bg = "#009900"
		self.fg = "#ffffff"	
		# Creating panel containing main actions' icons
		panel = Frame(parent, background="white")
		# Adding Start Scan button to panel
		self.start_img = PhotoImage(file='gui/images/scan.gif')
		self.start_btn = Button(panel, state='disabled', image=self.start_img, width=25, height=25)
		self.start_btn.pack(side=LEFT, padx=2)
		self.balloon.bind(self.start_btn, 'Start Scanning')
		
		# Adding Stop Scan button to panel
		self.stop_img = PhotoImage(file='gui/images/stop.gif')
		self.stop_btn = Button(panel, image=self.stop_img, state='disabled')
		self.stop_btn.pack(side=LEFT, padx=2)
		self.balloon.bind(self.stop_btn, 'Stop Scanning')
		
		# Adding Dump scan results button to panel
		self.dump_img = PhotoImage(file='gui/images/dump.gif')
		dump_btn = Button(panel, image=self.dump_img, state='disabled', width=25, height=25)
		dump_btn.pack(side=LEFT, padx=2)
		self.balloon.bind(dump_btn, 'Dump Scan Results')
		
		# Adding in-depth scanning of selected device/network button to panel
		self.sniff_img = PhotoImage(file='gui/images/duck.gif')
		self.sniff_btn = Button(panel, state='disabled', image=self.sniff_img, width=25, height=25)
		self.sniff_btn.pack(side=LEFT, padx=2)
		self.balloon.bind(self.sniff_btn, 'Sniff or Capture packets on selected interface')

		# Adding button to choose wireless interface
		self.choose_iface = Button(panel, text="Interface: None", fg="red", activeforeground="blue")
		self.choose_iface.pack(side=LEFT, padx=20, pady=2)
		self.balloon.bind(self.choose_iface, 'The %s has been selected for packet capture.'%self.choose_iface['text'])
				
		# Adding scan filter area
		filter_area = Frame(panel, highlightbackground="gray", highlightthickness=1)
		filter_lbl = Label(filter_area, text="Filter:").pack(side=LEFT)
		filter_entry = Entry(filter_area, width=30, borderwidth=0).pack(side=LEFT,expand=YES, fill=X)
		filter_area.pack(side=LEFT, expand=YES, fill=X, padx=30)
		self.balloon.bind(filter_area, 'Enter the scan filter value here')
		
		# Adding labels for graph and table views
		self.graph_btn = Button(panel, text="Graph", activeforeground="blue", command=lambda x="graph": self.create_items(x))
		self.graph_btn.pack(side=RIGHT)
		self.balloon.bind(self.graph_btn, 'Click to view Graphical plot of wireless scan results')
		self.table_btn = Button(panel, text="Table", activeforeground="blue", command=lambda y="table": self.create_items(y))
		self.table_btn.pack(side=RIGHT)
		self.balloon.bind(self.table_btn, 'Click to view Tabular view of wireless scan results')
		
		panel.pack(anchor=N, side=TOP, fill=X, expand=YES)
		
		# Container contains the canvas
		self.container = Frame(parent, bg="white")
		self.container.configure(highlightbackground="black", highlightthickness=5)
		
		# Creating a scrollbar for the canvas
		self.scrollY1 = Scrollbar(self.container, orient=VERTICAL)
		
		self.CANVAS_SIZE = 900	
		self.canvas1 = Canvas(self.container, width=self.CANVAS_SIZE, height=670, background='white')
		self.canvas1["scrollregion"] = (0,0,self.CANVAS_SIZE,self.CANVAS_SIZE)
		global canvas
		canvas = self.canvas1
		
		self.scrollY1.configure(command=self.canvas1.yview)
		# Binding Mousewheel event to canvas for vertical scrolling
		self.canvas1.bind("<MouseWheel>", lambda event: self.canvas1.yview('scroll', 1, 'units'))
		self.canvas1.bind('<4>', lambda event : self.canvas1.yview('scroll', -1, 'units'))
		self.canvas1.bind('<5>', lambda event : self.canvas1.yview('scroll', 1, 'units'))
			
		self.canvas1["yscrollcommand"] = self.scrollY1.set			
				
		self.listresult = Frame(self.container, bg="gray", width=1200, height=700)
		self.create_welcome()
				
		self.container.pack(fill=BOTH, expand=YES, anchor='center')
		self.count = 0
	
	# Creating the Home display or Welcome window of the Program
	# It lists the available interfaces in the computer on Left side and the Image slider on the right side.
	def create_welcome(self):
		# Main container in welcome window
		self.win = Frame(self.container, bg="gray")
		# Creates Title or introduction of the Program.
		win_title = Label(self.win, text="Wireless Scanner and Analyzer", font="Verdana 18 bold", bg = self.bg, fg=self.fg).pack(ipadx=10, ipady=10, fill=BOTH, padx=5, pady=5)
		win_body = Frame(self.win, background="gray")
		
		# Container containing list of available interfaces in the Computer.
		iface_box = Frame(win_body,  height=450, bg="gray", highlightbackground="gray", highlightthickness=1)
		
		# Defining images representing interfaces
		self.img_eth = PhotoImage(file="gui/images/eth.gif")
		self.img_wlan = PhotoImage(file="gui/images/wlan.gif")
		self.img_help = PhotoImage(file="gui/images/help.gif")
		
		# Getting list of Interfaces available in the computer
		self.interfaces = ListInterfaces().getAllInterfaces()
		iface_box_top = Frame(iface_box, highlightbackground=self.bg, highlightthickness=2)
		iface_title = Label(iface_box_top, text="Interfaces", width=20, bg=self.bg, fg=self.fg, font="Verdana 16 bold").pack(fill=X)
		for i in self.interfaces:
			# Displays Interfaces as a Label
			iface_lbl1 = Label(iface_box_top, text=i.title(), width=20, font="Verdana 12 bold", cursor="hand2", bg="gray")
			img1_lbl = Label(iface_lbl1, image=self.img_eth, bg="gray").pack(side=LEFT, padx=5)
			iface_lbl1.pack(anchor=W, ipady=5, pady=5, padx=2, fill=X)
			iface_lbl1.bind("<Enter>", lambda e: e.widget.config(background="tan"))
			iface_lbl1.bind("<Leave>", lambda e: e.widget.config(background="gray"))
			iface_lbl1.bind("<Button-1>", lambda event, iface=i: self.select_interface(event, iface))
		iface_box_top.pack(fill=X)
		
		# Container for list of Wireless Interfaces.
		iface_box_bottom = Frame(iface_box, highlightbackground=self.bg, highlightthickness=2)
		iface_title2 = Label(iface_box_bottom, text="Wireless Interfaces", bg=self.bg, fg=self.fg, width=20, font="Verdana 16 bold").pack(fill=X)
		
		# Getting list of wireless interfaces in the system
		self.w_interfaces = GetInterfaceList().getIface()
		for iface, mode in self.w_interfaces:
			text = "%s (Mode: %s)" % (iface.title(), mode.title())
			iface_lbl2 = Label(iface_box_bottom, text=text, width=20, font="Verdana 12 bold", cursor="hand2", bg="gray")
			img2_lbl = Label(iface_lbl2, image=self.img_wlan, bg="gray").pack(side=LEFT, padx=5)
			iface_lbl2.pack(anchor=W, ipady=5, pady=5, padx=2, fill=X)
			iface_lbl2.bind("<Enter>", lambda e: e.widget.config(background="tan"))
			iface_lbl2.bind("<Leave>", lambda e: e.widget.config(background="gray"))
			iface_lbl2.bind("<Button-1>", lambda event, iface=iface, mode=mode: self.select_interface(event, iface, mode))
		iface_box_bottom.pack(pady=10, fill=X) 
		
		# Container for putting Help information
		help_box = Frame(iface_box, highlightbackground=self.bg, highlightthickness=2)
		help_title = Label(help_box, text="Help", width=20, bg=self.bg, fg=self.fg, font="Verdana 16 bold").pack(fill=X)
		# Link to Documentation of the program.
		help_lbl = Label(help_box, text="Read Documentation", width=20, font="Verdana 12 bold", cursor="hand2", bg="gray")
		help_img = Label(help_lbl, image=self.img_help, bg="gray").pack(side=LEFT, padx=5)
		help_lbl.pack(anchor=W, ipady=5, pady=5, padx=2, fill=X)
		help_lbl.bind("<Enter>", lambda e: e.widget.config(background="tan"))
		help_lbl.bind("<Leave>", lambda e: e.widget.config(background="gray"))
		help_lbl.bind("<Button-1>", read_documentation)
		help_box.pack(fill=X)
		
		iface_box.pack(side=LEFT, anchor=NW, ipadx=5, ipady=5, padx=5, pady=5, expand=YES, fill=X)
		
		right_box = Frame(win_body, width=500, height=500, highlightbackground="green", bg="green", highlightthickness=1)
		self.slide1_image = PhotoImage(file="gui/images/slide1.gif")
		slide1 = Label(right_box, image=self.slide1_image, width=500, height=500).pack(expand=YES, fill=BOTH)
		right_box.pack(side=LEFT, anchor=NE, ipadx=5, ipady=5, padx=5, pady=5, expand=YES, fill=BOTH)
		win_body.pack(ipadx=5, ipady=5, fill=BOTH, expand=YES)
		bottom_lbl = Label(self.win, text="Copyright: Sajjan Bhattarai\n2014", font="Verdana 8 underline").pack(fill=X, padx=5, pady=5)
		self.win.pack(expand=YES, fill=BOTH)
	
	# Displays or creates items in the main window according to user's view preference.
	# This function is aimed to be run after the capture interface is selected and the Sniffer or Scanner is initiated.
	def create_items(self, view):
		if view == "graph":
			self.graph_btn.configure(background=self.bg, foreground=self.fg)
			self.table_btn.configure(background=self.fg, foreground="black")
			self.scrollY1.pack(fill=Y, side=RIGHT, expand=FALSE)
			self.canvas1.pack()
			self.win.pack_forget()
			self.listresult.pack_forget()
		elif view == "table":
			self.table_btn.configure(background=self.bg, foreground=self.fg)
			self.graph_btn.configure(background=self.fg, foreground="black")
			self.listresult.pack(expand=YES, fill=BOTH)
			self.scrollY1.pack_forget()
			self.canvas1.pack_forget()
	
	def scan_ap(self, iface, canvas):
		self.create_items("graph")
		table = Toplevel()
	    	table.title("Wireless Scanning: Access Points")
	    	scan = ThreadedClient()
	    	scan.main(table, iface, canvas, "position")
	    	self.stop_btn.configure(state='normal', command=scan.endApplication)
	    	table.mainloop()
		
	# Creating function to handle events occured on interfaces' list
	def select_interface(self, event, iface, mode=""):
		if mode != "":
			if mode != "monitor":
				ask_user = tkMessageBox.askokcancel(title="Turn on Monitor mode", message="Monitor Mode isn't yet enabled on this interface. Turn Monitor mode on %s interface?"%iface)
				if ask_user > 0 :
					os.system("sudo -A ifconfig %s down" % iface)
					os.system("sudo iwconfig %s mode monitor" % iface)
					os.system("sudo ifconfig %s up" % iface)
					event.widget.configure(text="%s (Mode: Monitor)" %iface.title())
				else:
					return
			self.start_btn.configure(state='normal', command=lambda i=iface, canvas=self.canvas1: self.scan_ap(i, canvas))
		else:
			self.start_btn.configure(state='disabled')
		self.interface = iface
		global interface
		interface = self.interface
		self.sniff_btn.configure(state='normal', command=lambda i=iface: self.sniffall(i))
		self.choose_iface.configure(fg=self.bg, text="Interface: %s"%self.interface)
		self.balloon.bind(self.choose_iface, 'The %s has been selected for packet capture.'%self.choose_iface['text'])
		
	def sniffall(self, iface):
		self.listresult.pack(expand=YES, fill=BOTH)
		if self.count == 0:
			st = self.SniffTable(self.listresult)
		sniff = ThreadSniffer()
		sniff.main(self.table, self.canvas, iface)
		self.stop_btn.configure(state='normal', command=sniff.endApplication)
		self.win.pack_forget()
		self.count += 1

	def SniffTable(self, parent):
		# Creating vertical scrollbar on the right side
		vscrollbar = Scrollbar(parent, orient=VERTICAL)
		
		# Creating canvas in order to make the widgets be scrollable.
		self.canvas = Canvas(parent, yscrollcommand=vscrollbar.set, height=700)
		vscrollbar.pack(fill=Y, side=RIGHT, expand=FALSE)
		
		# Creating table using Frame
		self.table = Frame(self.canvas, height=700)

		# Creating color definitions
		self.bg = "#009900"
		self.fg = "#ffffff"
		
		# Creating Table header
		table_head = Frame(parent)
		col0 = Label(table_head, width=3, text="SN", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthickness=1).pack(side=LEFT,fill=X)
		col1 = Label(table_head, width=7, text="Protocol", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT,fill=X)
		col2 = Label(table_head, width=20, text="Source", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthickness=1).pack(side=LEFT,fill=X)
		col3 = Label(table_head, width=20, text="Destination", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT,fill=X)
		col4 = Label(table_head, width=12, text="Type", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT,fill=X)
		col5 = Label(table_head, width=8, text="Subtype", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT,fill=X)
		col6= Label(table_head, width=16, text="SSID", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT,fill=X)
		col8 = Label(table_head, width=100, text="Info", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT,fill=X)
		
		# Packing table header and table into the GUI layout
		table_head.pack(side=TOP, fill=X, expand=YES, padx=2)
		#self.table.pack(expand=YES,fill=BOTH)
		# Packing canvas widget into the window
		self.canvas.pack(expand=YES, padx=2, anchor=NW)
		#self.canvas['scrollregion'] = '0 0 800 9999999999'
		vscrollbar.configure(command=self.canvas.yview)
		self.cw = self.canvas.create_window(0,0, window=self.table, anchor=NW, tags="table")
		
		# track changes to the canvas and frame width and sync them also updating the scrollbar
		self.table.bind('<Configure>', self._configure_table)
		self.canvas.bind('<Configure>', self._configure_canvas)
	
	# Functions to track and update canvas's size and table's sizes accordingly.	
	def _configure_table(self, event):
		# update the scrollbars to match the size of the table
		size = (self.table.winfo_reqwidth(), self.table.winfo_reqheight())
		self.canvas.configure(scrollregion="0 0 %s %s" % size)
		if self.table.winfo_reqwidth() != self.canvas.winfo_width():
			# update the canvas's width to fit the inner table
			self.canvas.configure(width=self.table.winfo_reqwidth())
		
	def _configure_canvas(self, event):
		if self.table.winfo_reqwidth() != self.canvas.winfo_width():
			# update the inner table's width to fill the canvas
			self.canvas.itemconfigure(self.cw, width=self.canvas.winfo_width())		
