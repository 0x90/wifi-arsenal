try:
	from Tkinter import *
	import Queue
	import Pmw
	from positioning.positions import GraphPositions
except ImportError, e:
	pass

class Gui(object):
	def __init__(self, parent, queue, endCommand, canvas):
		self.parent = parent
		Pmw.initialise()
		self.balloon = Pmw.Balloon(parent)
		self.queue = queue
		self.canvas = canvas
		
		if self.canvas != "":
			# Instantiate GraphPositions class to display graphical view of wireless devices found.
			self.pos = GraphPositions(canvas)
		
		# Creating main container for all widgets
		container = Frame(parent, highlightbackground="black", highlightthickness=3)
		
		# Creating vertical scrollbar on the right side
		vscrollbar = Scrollbar(container, orient=VERTICAL)
		
		# Creating canvas in order to make the widgets be scrollable.
		self.canvas = Canvas(container, yscrollcommand=vscrollbar.set)
		vscrollbar.pack(fill=Y, side=RIGHT, expand=FALSE)
		
		# Creating table using Frame
		self.table = Frame(container)
		
		# Creating a actionbar
		bar = Frame(parent, bd=1)
		bar.pack(side=TOP, fill=X)
		
		
		def endsniff():
			endCommand()
			scan = "Scan: Stopped"
			scan_display['text'] = scan
			scan_display['foreground'] = "red"

		# Adding Stop Scan button to bar
		self.stop_img = PhotoImage(file='gui/images/stop.gif')
		stop_btn = Button(bar, image=self.stop_img, command=endsniff)
		stop_btn.pack(side=LEFT, padx=2)
		self.balloon.bind(stop_btn, 'Stop Scanning')
		
		# Adding Interface display to bar
		self.iface_display = Label(bar, text="Interface: ", highlightbackground="black", highlightthickness=1)
		self.iface_display.pack(side=LEFT, padx=20)
		
		# Adding Scan Mode display to bar
		scan = "Scan: Running"
		scan_display = Label(bar, text=scan, highlightbackground="black", highlightthickness=1, foreground='green')
		scan_display.pack(side=RIGHT)
		
		# Creating color definitions
		self.bg = "#009900"
		self.fg = "#ffffff"
		# Creating Title
		title = Label(self.table, font="verdana 16 bold", text="Scan Results", bg=self.bg, fg=self.fg).pack(fill=X)
		#Button(self.table, text='Done', command=endCommand).pack()
							
		# Creating Table header
		table_head = Frame(self.table)
		col0 = Label(table_head, width=2, text="SN", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthickness=1).pack(side=LEFT)
		col1 = Label(table_head, width=7, text="Channel", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT)
		col2 = Label(table_head, width=25, text="SSID", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthickness=1).pack(side=LEFT)
		col3 = Label(table_head, width=18, text="BSSID", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT)
		col4 = Label(table_head, width=8, text="Signal", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT)
		col5 = Label(table_head, width=16, text="Encryption", background=self.bg, foreground=self.fg, highlightbackground=self.fg, highlightthicknes=1).pack(side=LEFT)
		self.sn = 0
		
		# Packing table header and table into the GUI layout
		table_head.pack(side=TOP)
		
		# Packing canvas widget into the window
		self.canvas.pack(expand=Y, padx=2)
		
		vscrollbar.configure(command=self.canvas.yview)
		self.cw = self.canvas.create_window(0,0, window=self.table, anchor=NW, tags="table")
		
		# track changes to the canvas and frame width and sync them also updating the scrollbar
		self.table.bind('<Configure>', self._configure_table)
		self.canvas.bind('<Configure>', self._configure_canvas)
		
		# Binding mousewheel move event to the canvas.		
		self.canvas.bind("<MouseWheel>", lambda event: self.canvas.yview('scroll', 1, 'units'))
		self.canvas.bind('<4>', lambda event : self.canvas.yview('scroll', -1, 'units'))
		self.canvas.bind('<5>', lambda event : self.canvas.yview('scroll', 1, 'units'))
		
		container.pack(expand=YES, fill=BOTH, padx=5, pady=5)
	
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
	
	def add_row(self, ch, essid, bssid, signal, enctype):
		self.sn += 1
		msg = "Access Point: %d \nChannel: %d \nESSID: %s \nBSSID: %s \nSignal strength: %s \nEncryption: %s" % (self.sn, ch, essid, bssid, signal, enctype)
		c1 = ch
		c2 = essid
		c3 = bssid
		c4 = signal
		c5 = enctype
		row = {}
		row[self.sn] = Frame(self.table)
		#self.balloon.bind(self.canvas, self.cw, msg)
		
		# function to bind same event to all children widgets inside specified widget.
		def bind_tree(widget, event, callback, add=''):
			widget.bind(event, callback, add)
			for child in widget.children.values():
				bind_tree(child, event, callback)
		
		col0 = Label(row[self.sn], text=self.sn, width=2, highlightbackground="black", highlightthickness=1).pack(side=LEFT)
		col1 = Label(row[self.sn], text=c1, width=7, highlightbackground="black", highlightthickness=1).pack(side=LEFT)
		col2 = Label(row[self.sn], text=c2, width=25, highlightbackground="black", highlightthickness=1).pack(side=LEFT)
		col3 = Label(row[self.sn], text=c3, width=18, highlightbackground="black", highlightthickness=1).pack(side=LEFT)
		col4 = Label(row[self.sn], text=c4, width=8, highlightbackground="black", highlightthickness=1).pack(side=LEFT)
		col5 = Label(row[self.sn], text=c5, width=16, highlightbackground="black", highlightthickness=1).pack(side=LEFT)
		row[self.sn].pack(side=TOP)
		
		bind_tree(row[self.sn], "<Enter>", lambda e: e.widget.configure(bg="yellow"))
		bind_tree(row[self.sn], "<Leave>", lambda e: e.widget.configure(bg="white"))
		
		# Binding mousewheel move event to the canvas.
		bind_tree(row[self.sn], "<4>", lambda event : self.canvas.yview('scroll', -1, 'units'))
		bind_tree(row[self.sn], "<5>", lambda event : self.canvas.yview('scroll', 1, 'units'))
		
		self.rmenu = Menu(row[self.sn], tearoff=0)
		self.rmenu.add_command(label="Details")
		self.rmenu.add_command(label="Connect")
		self.rmenu.add_command(label="De-Auth")
		row[self.sn].bind("<Button-3>", self.popup)
	
	def popup(self, event):
		self.rmenu.post(event.x_root, event.y_root)
	
	def processIncoming(self):
		""" Handle all messages currently in the queue, if any. """
		while self.queue.qsize():
		    try:
			msg = self.queue.get(0)
			# Check contents of message and do whatever is needed. As a
			# simple example, let's print it (in real life, you would
			# suitably update the GUI's display in a richer fashion.).
			self.iface_display['text'] = "Interface: %s" % msg[6]
			self.add_row(msg[1], msg[2], msg[3], msg[4], msg[5])
			if self.canvas != "":
				s = int(msg[4][1] + msg[4][2])
				self.pos.calc_position(msg[0], msg[1], msg[2], msg[3], s, msg[5])
		    except Queue.Empty:
			# Just on general principles, although we don't expect this
			# branch to be taken in this case, ignore this exception!
			pass
