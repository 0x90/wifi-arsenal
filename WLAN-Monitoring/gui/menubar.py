#!/usr/bin/env python

import sys
from Tkinter import *
import tkMessageBox as box
import tkColorChooser, tkFileDialog
from about import About
from wireless.menu_functions import *

view = ""
class MenuBar(object):
	def __init__(self, parent):
		#interface = container.interface
		self.myParent = parent
		self.ment = StringVar()
		#mLabel = Label(parent, text="My Label").pack()
		#mEntry = Entry(parent, textvariable=self.ment).pack()
		#mbutton = Button(parent, text = 'OK', command = self.mhello).pack()

		menuBar = Menu(parent)
		# Creating File menu
		filemenu = Menu(menuBar)
		filemenu.add_command(label="New", command = self.mNew)
		filemenu.add_command(label="Open", command = self.mOpen)
		filemenu.add_command(label="Save", command = self.mSave)
		filemenu.add_command(label="Exit", command = self.mQuit)

		menuBar.add_cascade(label="File", menu=filemenu)

		# Creating View menu
		view = Menu(menuBar)
		view.add_command(label="Tabular", command = self.show_table)
		view.add_command(label="Graphical", command = self.show_graph)

		menuBar.add_cascade(label="View", menu=view)

		# Creating Scan Menu
		scan = Menu(menuBar)
		scan.add_command(label="Access Points", command = lambda iface="": scan_ap(iface))
		scan.add_command(label="Clients", command = lambda iface="": scan_client(iface))
		scan.add_command(label="All", command = lambda iface="":scan_all(iface))

		menuBar.add_cascade(label="Scan", menu=scan)

		# Creating Analysis menu
		ana = Menu(menuBar)
		ana.add_command(label="Authentication")
		ana.add_command(label="Interference")

		menuBar.add_cascade(label="Analysis", menu=ana)

		# Creating Help menu
		helpmenu = Menu(menuBar)
		helpmenu.add_command(label="About", command=self.about)
		helpmenu.add_command(label="Documentation")
		helpmenu.add_command(label="Online Help")
		menuBar.add_cascade(label="Help", menu=helpmenu)

		parent.config(menu=menuBar)
	
	# for view>Graphical
	def show_graph(self):
		view = "graph"
	
	def show_table(self):
		view = "table"
	
	def about(self):
		about_win = Toplevel()
		about_win.title("About")
		ab = About(about_win)
		about_win.mainloop()
        
	def mhello(self):
		mtext = self.ment.get()
		mlabel1 = Label(self.myParent, text=mtext).pack()
		return
        
	def mNew(self):
		mlabel3 = Label(self.myParent, text="You clicked New.").pack()
		return

	def mOpen(self):
		myopen = tkFileDialog.askopenfile()
		mlabel5 = Label(self.myParent, text = myopen).pack()
		return
		
	def mSave(self):
		mlabel4 = Label(self.myParent, text="You clicked save.").pack()
		return

	def mQuit(self):
		mExit = box.askokcancel(title="Quit", message="Do you really want to exit?")
		if mExit > 0 :
			import os
			try:
				from container import interface
			except ImportError:
				pass
			if interface:
				os.system("sudo ifconfig %s down" % interface)
				os.system("sudo iwconfig %s mode managed" % interface)
				os.system("sudo ifconfig %s up" % interface)
			self.myParent.destroy()
            	return
