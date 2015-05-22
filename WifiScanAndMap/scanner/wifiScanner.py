#!/usr/bin/env python

'''
   Copyright 2010 Filia Dova, Georgios Migdos

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

import subprocess
import threading
import time
from gps import *
import os
import sys
from os import path
import commands


#======================================================================================================================

#--- Simple helper class:
#--- (method names are self-explanatory)

class Utilities:
	def getWirelessInterfacesList(self):
		networkInterfaces=[]		
		command = ["iwconfig"]
		process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		process.wait()
		(stdoutdata, stderrdata) = process.communicate();
		output = stdoutdata
		lines = output.splitlines()
		for line in lines:
			if(line.find("IEEE 802.11")!=-1):
				networkInterfaces.append(line.split()[0])
		return networkInterfaces
		
	def checkIfGpsdIsRunning(self):
		output = commands.getoutput('ps -A')
		if 'gpsd' in output:
    			return True
    		else:
    			return False


#======================================================================================================================

#--- Class that calls iwlist periodically
#--- and parses its output - also gets GPS data from gpsd:

class wifiScanner(threading.Thread):

	def __init__(self, wifiNetworks, interval):
		self.stopThread = threading.Event()
		self.wifiNetworks = wifiNetworks
		self.interval = interval
		self.setWirelessInterface(None)
		self.session = gps(mode=WATCH_ENABLE)
		self.scanning = False
		threading.Thread.__init__(self)
		
	def run(self):
		self.stopThread.clear()
		self.scanning = True
		
		while( not self.stopThread.isSet() ):
			self.scanForWifiNetworks()			
			time.sleep(self.interval)
		
		self.scanning = False
		
	
	def stop(self):
		self.stopThread.set()
		
	def isScanning(self):
		return self.scanning
			
	def getGPSData(self):
		#	Get GPS data from gpsd 
		# a = altitude, d = date/time, m=mode,
    # o=postion/fix, s=status, y=satellites
		#self.session.query('o')    		
		self.session.next()
		longtitude = self.session.fix.longitude
		latitude = self.session.fix.latitude
		return (longtitude, latitude)
		
	def getWifiNetworksList(self):
		result = []
		for k,v in self.wifiNetworks.iteritems():
			result.append(v)				
		return result
		
	def setWirelessInterface(self, iface):
		self.wIface = iface
		
	def getWirelessInterface(self):
		return self.wIface
		
		
	def scanForWifiNetworks(self):
		networkInterface = self.wIface
		output = ""
		if(networkInterface!=None):		
			command = ["iwlist", networkInterface, "scanning"]
			process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			process.wait()
			(stdoutdata, stderrdata) = process.communicate();
			output =  stdoutdata
			self.parseIwlistOutput(output)
	
	
	def cutFrom(self, s, pattern):
		index = s.find(pattern)
		if(index>-1):
			return s[index+len(pattern):]
		else:
			return ""
		
	def cutTo(self, s, pattern):
		index = s.find(pattern)
		if(index>-1):
			return s[:index]
		else:
			return s
		
	def parseIwlistOutput(self, output):
		output = self.cutFrom(output, "Address:")
		while (output!=""):	
			entry = self.cutTo(output, "Address:")
	
			address = ""
			essid = ""
			mode = ""
			channel = ""
			frequency = ""
			quality = ""
			signal = ""
			noise = ""
			encryption = ""
	
			address = entry[1:18]
	
			startIndex = entry.find("ESSID:\"")
			if(startIndex > -1):		
				endIndex = entry.find("\"\n", startIndex)
				essid = entry[startIndex+7:endIndex]
	
			startIndex = entry.find("Mode:")
			if(startIndex > -1):
				endIndex = entry.find("\n", startIndex)
				mode = entry[startIndex+5:endIndex]
	
			startIndex = entry.find("Channel:")
			if(startIndex > -1):
				endIndex = entry.find("\n", startIndex)
				channel = entry[startIndex+8:endIndex]
		
			startIndex = entry.find("Frequency:")
			if(startIndex > -1):
				endIndex = entry.find("\n", startIndex)
				frequency = entry[startIndex+10:endIndex]
		
			startIndex = entry.find("Quality=")
			if(startIndex > -1):
				endIndex = entry.find("Signal", startIndex) -2
				qual = eval(entry[startIndex+8:endIndex]+".0")
				if(qual > 1.0):
					qual = 1.0
				quality = str(qual)
	
			startIndex = entry.find("Signal level:")
			if(startIndex > -1):
				endIndex = entry.find("dBm", startIndex) -1
				signal = entry[startIndex+13:endIndex]
	
			startIndex = entry.find("Noise level=")
			if(startIndex > -1):
				endIndex = entry.find("dBm", startIndex) -1
				noise = entry[startIndex+12:endIndex]
	
			startIndex = entry.find("Encryption key:")
			if(startIndex > -1):
				endIndex = entry.find("\n", startIndex)
				encryption = entry[startIndex+15:endIndex]
			
			longtitude, latitude = self.getGPSData()
			
			key = (address, essid)
			value = [address, essid, mode, channel, frequency, quality, signal, noise, encryption, str(latitude), str(longtitude)]
			try:
				oldValue = self.wifiNetworks[key]				
				qualityN = eval(quality)
				oldQualityN = eval(oldValue[5])
				oldLat = oldValue[9]
				oldLon = oldValue[10]				
				if ( ( qualityN >  oldQualityN) or ( (oldLat=="0.0") and (oldLon=="0.0") ) ):
					self.wifiNetworks[key] = value
			except KeyError:
				self.wifiNetworks[key] = value
			
			output = self.cutFrom(output, "Address:")



	def exportXML(self, filename):
		out = open(filename, 'w')
		out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
		out.write("<networkslist>\n")
		
		lst = self.getWifiNetworksList()
		for l in lst:
			out.write("\t<network>\n")
			
			out.write("\t\t<address>"+ l[0] +"</address>\n")
			out.write("\t\t<essid>"+ l[1] +"</essid>\n")
			out.write("\t\t<mode>"+ l[2] +"</mode>\n")
			out.write("\t\t<channel>"+ l[3] +"</channel>\n")
			out.write("\t\t<frequency>"+ l[4] +"</frequency>\n")
			out.write("\t\t<quality>"+ l[5] +"</quality>\n")
			out.write("\t\t<signal>"+ l[6] +"</signal>\n")
			out.write("\t\t<noise>"+ l[7] +"</noise>\n")
			out.write("\t\t<security>"+ l[8] +"</security>\n")
			out.write("\t\t<latitude>"+ l[9] +"</latitude>\n")
			out.write("\t\t<longtitude>"+ l[10] +"</longtitude>\n")
			
			out.write("\t</network>\n")
			
		out.write("</networkslist>\n")
		out.close()



#======================================================================================================================

#--- Class that is used to print
#--- results to stdout

class resultCLIPrinter(threading.Thread):

	def __init__(self, interval, scanner, msg):
		self.stopThread = threading.Event()
		self.scanner = scanner
		self.interval = interval
		self.msg = msg
		threading.Thread.__init__(self)

	def run(self):
		self.stopThread.clear()
		
		while( not self.stopThread.isSet() ):
			os.system("clear")					
			lst = self.scanner.getWifiNetworksList()
			for l in lst:
				print l
			print "--------------------"
			print self.msg
			time.sleep(self.interval)
		
	
	def stop(self):
		self.stopThread.set()
		




#======================================================================================================================

#--- Simple CLI application:

class CLIApplication:

	def __init__(self):	
		self.wifiNetworks={}
		self.SCANNER_INTERVAL = 5
		self.UPDATE_INTERVAL = 2
		self.checkForGpsd()	
		self.scanner = wifiScanner(self.wifiNetworks, self.SCANNER_INTERVAL)
		self.resultsPrinter = resultCLIPrinter(self.UPDATE_INTERVAL, self.scanner, "Press enter key to stop scanning")
		
	def checkForGpsd(self):
		if( not Utilities().checkIfGpsdIsRunning()):
			print "gpsd is not running!"
			device = raw_input("Please enter which GPS device gpsd should use: ")
			while (not os.path.exists(device)):
				print "Invalid device!"
				device = raw_input("Please enter which GPS device gpsd should use: ")
			process = subprocess.Popen(["gpsd", device])
			process.wait()
	
	def run(self):
		os.system("clear")
		print "Available wireless interfaces:"
		wifiInterfacesList = Utilities().getWirelessInterfacesList()
		if(len(wifiInterfacesList)==0):
			print "\tNone\n"
			print "Get a wireless card and try again! Bye, bye..."
			exit(1)
		else:
			for wi in wifiInterfacesList:
				print "\t- "+wi
		
		wifiInterfaceName = raw_input("Wireless interface to use: ")
		if( not (wifiInterfaceName in wifiInterfacesList) ):
			print "Error: Invalid wireless interface!"
			exit(1)
				
		self.scanner.setWirelessInterface(wifiInterfaceName)
				
		self.scanner.start()
		self.resultsPrinter.start()
		
		x=raw_input()		
		
		self.resultsPrinter.stop()
		self.scanner.stop()
				
		answer = raw_input("Would you like to save the results as an XML file (y = yes)? ")
		if(answer == "y"):
			fname = raw_input("Filename: ")
			self.scanner.exportXML(fname)
		


#======================================================================================================================

#--- GUI application:

class GUIApplication:

	def __init__(self):
		
		self.checkForGpsd()
					
		self.initialize()
		self.associateGUIElements()
		self.createComboBox()	
		self.createListview()
		self.bindEvents()
		
		self.updater = ListviewUpdater(self, self.discoveredLabel, self.UPDATE_INTERVAL)		
		self.updater.start()
								
		self.window.show_all()
		
			
	def initialize(self):
		self.wifiNetworks = {}
		self.SCANNER_INTERVAL = 5
		self.UPDATE_INTERVAL = 2
		self.scanner = wifiScanner(self.wifiNetworks, self.SCANNER_INTERVAL)
		self.gladefile = path.join(path.dirname(__file__), "wnmc.glade")
		self.wTree = gtk.glade.XML(self.gladefile)	
	
	def checkForGpsd(self):
		if( not Utilities().checkIfGpsdIsRunning()):
			device = self.showEnterGPSDeviceDialog('Please enter which <b> GPS device </b> to use:')
			while ( (device!=None) and (not os.path.exists(device)) ):
				device = self.showEnterGPSDeviceDialog('<b>Invalid device!</b>\nPlease enter which <b> GPS device </b> to use:')
			if(device==None):
				exit(0)
			process = subprocess.Popen(["gpsd", device])
			process.wait()
			
	def on_quit(self, sender, arg=None):
        	self.quit()
        
        def quit(self):
        	if(self.updater!=None):
        		self.updater.stop()
        	if(self.scanner!=None):
        		self.scanner.stop()        	
        	gtk.main_quit()
        	
	def run(self):		
		gtk.main()
		
	def getScanner(self):
		return self.scanner
	
	def getListview(self):
		return self.listview
	
	def getNetworks(self):
		return self.wifiNetworks
	
	def getNumberOfNetworks(self):
		return len(self.wifiNetworks)
	
#	def setRGBAColorMap(self, widget):
#		screen = widget.get_screen()
#		rgba = screen.get_rgba_colormap()
#		widget.set_colormap(rgba)
	
	def associateGUIElements(self):
		self.window = self.wTree.get_widget("window1")
		#self.setRGBAColorMap(self.window)
		self.scrolledWindow1 = self.wTree.get_widget("scrolledwindow1")
		self.statusLabel = self.wTree.get_widget("label1")
		self.discoveredLabel = self.wTree.get_widget("label3")
		self.quitButton = self.wTree.get_widget("button1")
		self.startStopButton = self.wTree.get_widget("button2")
		self.exportXMLButton = self.wTree.get_widget("button3")


# --- Network interface selection combobox:

	def createComboBox(self):
		self.comboBox1 =  gtk.combo_box_new_text()		
		self.wTree.get_widget("hbox1").pack_start(self.comboBox1, expand=False)
		self.updateComboBoxModel()
	
	def updateComboBoxModel(self):
		self.comboBox1.get_model().clear()
		items = Utilities().getWirelessInterfacesList()
		for item in items:
			self.comboBox1.append_text(item)
		if(len(items)>0):
			self.comboBox1.set_active(0)
		

#--- Wifi networks listview:

	def createListview(self):
		self.listviewModel = self.createListviewModel()
		self.listview = gtk.TreeView(self.listviewModel)		
		self.scrolledWindow1.add(self.listview)
		self.createListviewColumns(self.listview)
		self.listview.set_reorderable(False)
	
	
	def createListviewModel(self):
		networksList = []
		listviewModel = gtk.ListStore(str, str, str, str, str, float, str, str, gtk.gdk.Pixbuf, str, str)				
		return listviewModel
		
	def createListviewColumns(self, listview):	
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("ESSID", rendererText, text=1)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Address", rendererText, text=0)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Mode", rendererText, text=2)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Channel", rendererText, text=3)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Frequency", rendererText, text=4)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererProgress = gtk.CellRendererProgress()
		column = gtk.TreeViewColumn("Quality", rendererProgress, value=5)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Signal", rendererText, text=6)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Noise", rendererText, text=7)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererPixbuf = gtk.CellRendererPixbuf()
		column = gtk.TreeViewColumn("Security", rendererPixbuf, pixbuf=8)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Latitude", rendererText, text=9)
		column.set_sort_column_id(-1)
		listview.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Longtitude", rendererText, text=10)
		column.set_sort_column_id(-1)
		listview.append_column(column)
			
#--- GUI Events: 
	
	def bindEvents(self):
		self.startStopButton.connect("clicked", self.onStartStopButtonClicked)
		self.quitButton.connect("clicked", self.onQuitButtonClicked)
		self.exportXMLButton.connect("clicked", self.onExportXMLButtonClicked)
		
		if (self.window):
			self.window.connect("destroy", self.on_quit)


	def onStartStopButtonClicked(self, widget):
		if(self.scanner.isScanning()):		
			self.stopScanning()
			self.updateComboBoxModel()
		else:
			self.startScanning()



	def onQuitButtonClicked(self, widget):
		self.quit()



	def onExportXMLButtonClicked(self, widget):
		self.exportXML()

#--- Application methods:

	def startScanning(self):
		if(self.comboBox1.get_active()!=-1):
			self.scanner.stop()
			
			self.comboBox1.set_sensitive(False)
			self.exportXMLButton.set_sensitive(False)
			self.startStopButton.set_label("Stop scanning")
			self.statusLabel.set_text("Scanning for 802.11 networks in range...")
			
			iface = self.comboBox1.get_model().get_value(self.comboBox1.get_active_iter(), 0)			
			self.scanner = wifiScanner(self.wifiNetworks, self.SCANNER_INTERVAL)
			self.scanner.setWirelessInterface(iface)
			self.scanner.start()
	
	def stopScanning(self):
		self.scanner.stop()
		self.startStopButton.set_label("Start scanning")
		self.startStopButton.set_sensitive(False)
		self.statusLabel.set_text("Stopping - Please wait...")
		while (self.scanner.isScanning()):
			time.sleep(1)
		self.statusLabel.set_text("Idle")
		self.startStopButton.set_sensitive(True)
		self.comboBox1.set_sensitive(True)
		self.exportXMLButton.set_sensitive(True)
				

	def exportXML(self):
		fname = self.getSaveTarget()
		if( fname!=None ):
			self.scanner.exportXML(fname)
	
	def getSaveTarget(self):
		filename = self.showSaveToXMLDialog()
		overwrite = False
		while( (filename!=None) and os.path.exists(filename) and (not overwrite) ):
			if(self.overwriteFile(filename)):
				overwrite = True
			else:
				filename = self.showSaveToXMLDialog()
		return filename
	
	def showSaveToXMLDialog(self):
		dialog = gtk.FileChooserDialog("Save..", self.window, gtk.FILE_CHOOSER_ACTION_SAVE, (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_SAVE, gtk.RESPONSE_OK))
		#self.setRGBAColorMap(dialog)
		dialog.set_default_response(gtk.RESPONSE_OK)
		filter = gtk.FileFilter()
		filter.set_name("XML files")
		filter.add_mime_type("text/xml")
		filter.add_pattern("*.xml")
		dialog.add_filter(filter)
		response = dialog.run()
		if response == gtk.RESPONSE_OK:				
			result = dialog.get_filename()
		elif response == gtk.RESPONSE_CANCEL:
			result = None
		dialog.destroy()
		return result
	
	def overwriteFile(self, filename):
		dialog = gtk.MessageDialog(self.window, gtk.DIALOG_MODAL, gtk.MESSAGE_WARNING, gtk.BUTTONS_YES_NO, "The file: \n\n"+filename+"\n\nalready exists. Overwrite?")
		#self.setRGBAColorMap(dialog)
		response = dialog.run()
		dialog.destroy()
		if response == gtk.RESPONSE_YES:				
		    return True
		elif response == gtk.RESPONSE_NO:
		    return False

	def showEnterGPSDeviceDialog(self, msg):
		dialog = gtk.MessageDialog(None, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION,  gtk.BUTTONS_OK_CANCEL, None)
		#self.setRGBAColorMap(dialog)
		dialog.set_markup(msg)
		entry = gtk.Entry()
		entry.connect("activate", self.responseToDialog, dialog, gtk.RESPONSE_OK)
		hbox = gtk.HBox()
		hbox.pack_start(gtk.Label("Device:"), False, 5, 5)
		hbox.pack_end(entry)
		dialog.vbox.pack_end(hbox, True, True, 0)
		dialog.show_all()
		response = dialog.run()
		device = entry.get_text()
		dialog.destroy()
		if response == gtk.RESPONSE_CANCEL:				
		    return None
		return device

	def responseToDialog(self, entry, dialog, response):
		dialog.response(response)


#======================================================================================================================

#--- Helper class that updates the listview on regular intervals:

class ListviewUpdater(threading.Thread):
			
	def __init__(self, parentApp, counterLabel, interval):
		self.stopThread = threading.Event()	
		self.parentApp = parentApp
		self.interval = interval
		self.counterLabel = counterLabel
		self.lockedIcon = gtk.gdk.pixbuf_new_from_file(path.join(path.dirname(__file__), "locked.png"))
		self.unlockedIcon = gtk.gdk.pixbuf_new_from_file(path.join(path.dirname(__file__), "unlocked.png"))
		threading.Thread.__init__(self)

	def run(self):
		self.stopThread.clear()
		
		while( not self.stopThread.isSet() ):
			scanner = self.parentApp.getScanner()
			listview = self.parentApp.getListview()
			
			networksList = scanner.getWifiNetworksList()
			listviewModel = gtk.ListStore(str, str, str, str, str, float, str, str, gtk.gdk.Pixbuf, str, str)
			for l in networksList:
				listviewModel.append( [ l[0], l[1], l[2], l[3], l[4], eval(l[5])*100, l[6], l[7], self.securityStatusToPixbuf(l[8]), l[9], l[10] ] )
			listviewModel.set_sort_column_id(5,gtk.SORT_DESCENDING) 
			gtk.gdk.threads_enter()
			listview.set_model(listviewModel)			
			self.counterLabel.set_markup("Networks found: <b>"+str(self.parentApp.getNumberOfNetworks())+"</b>")
			gtk.gdk.threads_leave()
			time.sleep(self.interval)
		
	
	def stop(self):
		self.stopThread.set()
		
		
	def securityStatusToBool(self, status):
		if(status=="on"):
			return True
		else:
			return False
			
	def securityStatusToPixbuf(self, status):
		if(status=="on"):
			return self.lockedIcon
		else:
			return self.unlockedIcon



#======================================================================================================================

#--- Main loop:


if "--no-gui" in sys.argv:
	import readline
	application = CLIApplication()
else:
	import gtk
	import gtk.glade
	gtk.gdk.threads_init()
	application = GUIApplication()

application.run()


