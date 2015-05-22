#!/usr/bin/env python

# Copyright (c) 2009 Emiliano Pastorino <emilianopastorino@gmail.com>
#
# Permission is hereby granted, free of charge, to any
# person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the
# Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the
# Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice
# shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
# KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
# OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
import pygtk
import gtk
import sys
import os.path
import commands
from filterer import Filterer
from plotter import Plotter
import threading
gtk.gdk.threads_init()
 
class SkyBlueTero(object):       
	def __init__(self):
		
		builder = gtk.Builder()
		builder.add_from_file(os.path.join('.','gui','gui.xml'))
		builder.connect_signals(self)

		self.window = builder.get_object("window1")
		self.win_wait = builder.get_object("window2")
		self.entry = builder.get_object("entry1")
		self.entry_filter_name = builder.get_object("entry2")
		self.chk_btn_crc = builder.get_object("checkbutton1")
		self.chk_btn_csv = builder.get_object("checkbutton2")
		self.entry_csv_decimal_sep = builder.get_object("entry4")
		self.entry_csv_values_sep = builder.get_object("entry5")
		self.entry_csv_savefile = builder.get_object("entry3")
		self.file_chooser = builder.get_object("filechooserbutton1")
		self.btn_load_filter = builder.get_object("filechooserbutton3")
		self.chk_btn_plot = builder.get_object("checkbutton3")
		self.combobox_plot_style = builder.get_object("combobox1")
		self.entry_save_filter = builder.get_object("entry8")
		self.fchooser_save_filter = builder.get_object("filechooserbutton2")
		self.entry_interval = builder.get_object("entry7")
		self.entry_title = builder.get_object("entry6")
		self.fchooser_csv = builder.get_object("filechooserbutton4")
		self.chkbtnOtherTraffic = builder.get_object("chkbtnOtherTraffic")
		self.btnClearFilterList = builder.get_object("btnClearFilterList")
		self.btnRicardoLink = builder.get_object("btnRicardoLink")

		self.treeView = builder.get_object("treeview1")
		self.liststore = gtk.ListStore(str,str)
		self.treeView.set_model(self.liststore)
		self.treeView.set_headers_visible(True)
		column = gtk.TreeViewColumn("Filter name",gtk.CellRendererText(),text=0)
		column.set_resizable(True)
		self.treeView.append_column(column)
		column = gtk.TreeViewColumn("Wireshark filter expression",gtk.CellRendererText(),text=1)
		column.set_resizable(True)
		self.treeView.append_column(column)

		self.window.show()
	
	# 'Add filter' button is pressed
	def on_button1_clicked(self,widget,data=None):
		if self.entry.get_text().strip() is not '':
			iter = self.liststore.append()
			if self.entry_filter_name.get_text().strip() is '':
				self.liststore.set_value(iter,0,'???')
			else:
				self.liststore.set_value(iter,0,self.entry_filter_name.get_text())
			self.liststore.set_value(iter,1,self.entry.get_text())
	
	# 'Remove selected filter' button is pressed
	def on_button2_clicked(self,widget,data=None):
		try:
			self.liststore.remove(self.treeView.get_selection().get_selected()[1])
		except:
			pass

	def on_filechooserbutton3_file_set(self,widget):
		try:
			f = open(widget.get_filename(),'r')
			for i in f.readlines():
				iter = self.liststore.append()
				self.liststore.set_value(iter,0,i.split(',')[0].strip())
				self.liststore.set_value(iter,1,i.split(',')[1].strip())
			f.close()
		except Exception,e:
			print e

	def on_button4_clicked(self,widget):
		if self.entry_save_filter.get_text().strip() is not '':
			try:
				f = open(os.path.join(self.fchooser_save_filter.get_filename(),self.entry_save_filter.get_text()),'w')
				paths=[]
				self.liststore.foreach(lambda model, path, iter, user_data: paths.append(path), None)
				for i in paths:
					iter = self.liststore.get_iter(i)
					f.write(self.liststore.get_value(iter,0) + ',' + self.liststore.get_value(iter,1) + '\n')
				f.close()
			except Exception,e:
				print e

	def on_button3_clicked(self,widget):
		self.waiting = True
		hilo = threading.Thread(target=self.show_waiting)
		hilo.start()
		otro_hilo = threading.Thread(target=self.process_data)
		otro_hilo.start()


	# 'GO' button is pressed
	def process_data(self):
		if self.chk_btn_plot.get_active() or self.chk_btn_csv.get_active():
			filters = []
			paths = []
			tags = []
			self.liststore.foreach(lambda model, path, iter, user_data: paths.append(path), None)
			for i in paths:
				iter = self.liststore.get_iter(i)
				filters.append([self.liststore.get_value(iter,0),self.liststore.get_value(iter,1)])
				tags.append(self.liststore.get_value(iter,0))
			if self.entry_interval.get_text().strip() is not '':
				interval = float(self.entry_interval.get_text())
			else:
				interval = 1
			if self.chkbtnOtherTraffic.get_active():
				othertrafficfilter = ''
				for i in filters:
					othertrafficfilter = othertrafficfilter + '!(' + i[1] + ') and '
				othertrafficfilter = othertrafficfilter[:-5]
				filters.append(['Other',othertrafficfilter])
				tags.append('Other')
			timeline,yvalues = Filterer(str(self.file_chooser.get_filename()).replace(' ','\ '),filters,interval,self.chk_btn_crc.get_active(),self.chk_btn_csv.get_active()).start()
			self.waiting = False

			if self.chk_btn_csv.get_active():
				dec_sep = self.entry_csv_decimal_sep.get_text()
                		values_sep = self.entry_csv_values_sep.get_text()
				sep_dec = self.entry_csv_decimal_sep.get_text()
				sep_val = self.entry_csv_values_sep.get_text()
				if self.entry_csv_savefile.get_text().strip() is not '':
					try:
						savepath = os.path.join(self.fchooser_csv.get_filename(),self.entry_csv_savefile.get_text())
						f = open(savepath,'w')
						f.write('TIME')
						for i in timeline:
							f.write(sep_val+str(i).replace('.',sep_dec))
						f.write('\n')
						for i in range(0,len(filters)):
							f.write(filters[i][0])
							for j in yvalues[i]:
								f.write(sep_val+str(j).replace('.',sep_dec))
							f.write('\n')
						f.close()
						print("%s succesfully created."%savepath)
					except Exception,e:
						print e
			gtk.gdk.threads_enter()
			self.window.set_opacity(1)
			self.win_wait.hide()
			if self.chk_btn_plot.get_active():
				plt = Plotter(timeline,yvalues,tags,self.entry_title.get_text())
				if self.combobox_plot_style.get_active() is 0:
					plt.simpleplot()
				elif self.combobox_plot_style.get_active() is 1:
					plt.stackareaplot()
				else: plt.simpleplot()
			gtk.gdk.threads_leave()


	def show_waiting(self):
		#while self.waiting:
			gtk.gdk.threads_enter()
			self.window.set_opacity(0.5)
			self.win_wait.show()
			gtk.gdk.threads_leave()
		#self.win_wait.hide()
		#self.window.show()
	

	def on_btnClearFilterList_clicked(self,widget):
		self.liststore.clear()

	def on_btnRicardoLink_clicked(self,widget):
		try:
			commands.getoutput('firefox %s'%widget.get_uri())
		except Exception,e:
			print e


	# Main window is closed
	def on_window1_destroy(self,widget,data=None):
		print "Thanks for using this program."
		print "Please, send comments, suggestions or bugs to emilianopastorino@gmail.com"
		sys.exit()	

if __name__ == "__main__":
	app = SkyBlueTero()
	gtk.main()
