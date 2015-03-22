#!/usr/bin/python

# Copyright (c) 2009 Emiliano Pastorino <emilianopastorino@gmail.com>
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
#

import os.path
import commands
import math
import threading

semaphore = threading.Semaphore(2)
airtimes=[]

class Filterer():

	def __init__(self,dumpfile,filters,time_unit,check_fcs,csv):
		global airtimes
		airtimes=[]
		self.dumpfile = dumpfile
		if not os.path.isfile(self.dumpfile):
			print('ERROR: File not found:%s'%self.dumpfile)
		self.filters = filters
		self.time_unit = time_unit
		self.check_fcs = check_fcs
		self.csv = csv


	def start(self):
		global airtimes
		for i in self.filters:
			airtimes.append('')
		if self.check_fcs:
			for j in range(0,len(self.filters)):
				self.filters[j][1]='wlan.fcs_good == 1 && ('+self.filters[j][1] + ')'
		j=0
		threads = []
		for i in self.filters:
			thread = TsharkThread(self.dumpfile,i[1],self.time_unit,j)
			j=j+1
			threads.append(thread)
			thread.start()
		for i in threads:
			i.join()
		size=0
		for i in airtimes:
			for j in range(0,len(i)):
				i[j] = i[j]*100.0
				
		for i in airtimes:
			if len(i) > size:
				size = len(i)
		for i in airtimes:
			while len(i) < size:
				i.append(0)
		timeline = []
		for i in range(0,size):
			timeline.append(i*self.time_unit)

		return timeline,airtimes

class TsharkThread(threading.Thread):
	def __init__(self,file,filter,time_unit,index):
		global airtimes
		threading.Thread.__init__(self)
		self.file = file
		self.filter = filter
		self.time_unit = time_unit
		self.index = index
	def run(self):
		semaphore.acquire()
		global airtimes
		datarates_b = ('2','4','11','22')
		datarates_g = ('12','18','24','36','48','72','96','108')
		lastslot = 0
		airtime = [0]
		output = commands.getoutput('tshark -r %s -R "%s" -T fields -e frame.time_relative -e radiotap.datarate -e frame.len'%(self.file,self.filter))
		output = output.split('\n')
		if output[0] is not '':
			for j in output:
				try:
					time,rate,size = j.split('\t')
				except:
					time=0
					rate=0
					size=0
				if rate in datarates_b:
					airsize = 192 + float(size) * 16 / float (rate)
				elif rate in datarates_g:
					airsize = 26 + float(size) * 16 / float (rate)
				else:
					airsize = 0
	   			timeslot = int(math.floor(float(time) / float(self.time_unit)))
	   			if timeslot > lastslot:
	      				for slot in range(lastslot, timeslot):
	        				airtime.append(0)
	   			airtime[timeslot] += airsize / (self.time_unit * 1000000)
	   			lastslot = timeslot
		else:
			print("No packets caught by filter %s."%self.filter)
			airtime=[]
		airtimes[self.index] = airtime
		semaphore.release()
