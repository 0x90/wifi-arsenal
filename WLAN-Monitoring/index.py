#!/usr/bin/env python

# Tries to import the required packages and classes
try:
	from Tkinter import *
	from gui.menubar import MenuBar
	from gui.container import DisplayBox
	from time import localtime, strftime
# passes the program execution if import wasn't successful
except ImportError, e:
	print e
	print "Please make sure that all the required libraries:\n Tkinter, Scapy, Pmw are installed and working properly in your system.\nPlease run this program later!"
	print "\n\n" + "="*50 + "\nExiting System."
	exit()
	
# Guards program execution	
if __name__ == '__main__':
	# variable to store current date and time.
	start_time = strftime("%Y-%m-%d %H:%M:%S", localtime())
	print "Start time: %s" % start_time
	
	# Instantiate Tk() to create new window
	root = Tk()
	#root.geometry("800x1000+300+300")
	
	# Read optionfile containing values for widget's attributes
	root.option_readfile("gui/optionDB")
	root.title("WLAN Manager")
	
	# Instantiating the class MenuBar to add Menu bar in the top of window
	mb = MenuBar(root)
	# Instantiating Displaybox class to add action panel and canvas in the main window
	db = DisplayBox(root)
	#db.create_box(root)
	root.mainloop()
