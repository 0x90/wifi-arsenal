try:
	from Tkinter import *
	import Pmw, Queue
except ImportError:
	pass

global no_rows
class ListResults(object):
	def __init__(self, parent, canvas, queue):
		self.parent = parent
		self.canvas = canvas
		self.queue = queue
		self.sn = 0
		
	def add_row(self, protocol, frame_type, subtype, src, dst, ssid, info):
		self.sn += 1
		#msg = "Access Point: %d \nChannel: %d \nESSID: %s \nBSSID: %s \nSignal strength: %s \nEncryption: %s" % (self.sn, ch, essid, bssid, signal, enctype)
		c1 = protocol
		c2 = src
		c3 = dst
		c4 = frame_type
		c5 = subtype
		c6 = ssid
		c7 = info
		row = {}
		row[self.sn] = Frame(self.parent)
		#self.balloon.bind(self.canvas, self.cw, msg)
		
		# function to bind same event to all children widgets inside specified widget.
		def bind_tree(widget, event, callback, add=''):
			widget.bind(event, callback, add)
			for child in widget.children.values():
				bind_tree(child, event, callback)
		
		col0 = Label(row[self.sn], text=self.sn, width=3, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		col1 = Label(row[self.sn], text=c1, width=7, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		col2 = Label(row[self.sn], text=c2, width=20, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		col3 = Label(row[self.sn], text=c3, width=20, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		col4 = Label(row[self.sn], text=c4, width=12, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		col5 = Label(row[self.sn], text=c5, width=8, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		col6 = Label(row[self.sn], text=c6, width=16, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		col7 = Label(row[self.sn], text=c7, width=100, highlightbackground="gray", highlightthickness=1).pack(side=LEFT,fill=X)
		row[self.sn].pack(side=TOP, fill=X)
		
		bind_tree(row[self.sn], "<Enter>", lambda e: e.widget.configure(bg="yellow"))
		bind_tree(row[self.sn], "<Leave>", lambda e: e.widget.configure(bg="white"))
		
		# Binding mousewheel move event to the canvas.
		bind_tree(row[self.sn], "<4>", lambda event : self.canvas.yview('scroll', -1, 'units'))
		bind_tree(row[self.sn], "<5>", lambda event : self.canvas.yview('scroll', 1, 'units'))

		self.rmenu = Menu(row[self.sn], tearoff=0)
		self.rmenu.add_command(label="Details")
		self.rmenu.add_command(label="Connect")
		self.rmenu.add_command(label="De-Auth")
		bind_tree(row[self.sn], "<Button-3>", self.popup)
					
	def popup(self, event):
		self.rmenu.post(event.x_root, event.y_root)
	
	def processIncoming(self):
		""" Handle all messages currently in the queue, if any. """
		while self.queue.qsize():
		    try:
			msg = self.queue.get(0)
			self.add_row(msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6])
		    except Queue.Empty:
			# Just on general principles, although we don't expect this
			# branch to be taken in this case, ignore this exception!
			pass
		
