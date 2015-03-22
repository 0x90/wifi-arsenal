#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    bunnyChat.py
#
#    Copyright 2013 W. Parker Thompson <w.parker.thompson@gmail.com>
#		
#    This file is part of Bunny.
#
#    Bunny is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Bunny is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Bunny.  If not, see <http://www.gnu.org/licenses/>.

import libbunny
import threading, getopt, sys, time

def usage():
	"""
	
	print out usage
	
	"""
	print "BunnyChat.py [COMANDS]"
	print " MODES:"
	print "  -c [UserName]   --   Chat client mode"
	print "  -l              --   Listen mode, gets packets and prints data"
	print "  -s [data]       --   Send mode, sends packets over and over"
	print "  -m              --   Passive profiling of all the channels (1-11)"
	print "  -r              --   Reloop shows the mod/remainder of the specified channel"
	print "  -p              --   Ping/Pong testing, Run this on one machine and it will"
	print "                        respond with a pong."
	print "  -k              --   Ping server mode, will repsond to pings with pong and current time"
	print "  -h 			 --   Shows this message"
	print ""
	# print " OPTIONS:"


def main():
	listen_mode = send_mode = scan_chans_mode = chat_mode = ping_mode_serv = ping_mode_client = reloop_mode = False
	
	# parse arguments
	try:
		opts, args = getopt.getopt(sys.argv[1:],"hlrmkpc:s:f:")
	except getopt.GetoptError as err:
		print str(err)
		usage()
		sys.exit(1)
	for opt, arg in opts:
		if opt == "-h":
			usage()
			sys.exit(0)
		elif opt == "-l": 
			listen_mode = True
		elif opt == "-r":
			reloop_mode = True
		elif opt == "-s":
			send_mode = True
			send_data = arg
		elif opt == "-m":
			scan_chans_mode = True
		elif opt == "-c":
			UserName = arg
			chat_mode = True
		elif opt == "-k":
			ping_mode_serv = True
		elif opt == "-p":
			ping_mode_client = True
	if listen_mode:
		print "Bunny in listen mode"
		print "Building model: . . . "
		bunny = libbunny.Bunny()
		print "Bunny model built and ready to listen"
		while True:
			print bunny.recvBunny()
		bunny.killBunny()
	elif reloop_mode:
		#bunny = libbunny.Bunny()
		inandout = libbunny.SendRec()
		inandout.reloop()
		
	elif send_mode:
		if send_data is not None:
			bunny = libbunny.Bunny()
			print "Bunny model built"
			bunny.model.printTypes()
			bunny.model.printMacs()
			print "sending message: %s" % send_data
			bunny.sendBunny(send_data)
			
			while True:
				print "again? [Y/N]"
				input = sys.stdin.readline()
				if input == "Y\n" or input == "y\n":
					print "sending message: %s" % send_data
					bunny.sendBunny(send_data)
				elif input == "N\n" or input == "n\n":
					bunny.killBunny()
					sys.exit()
		else:
			print usage()
			sys.exit()
			
	elif chat_mode:
		print "chat client mode:"
		print "building traffic model: . . "
		bunny = libbunny.Bunny()
		
		print "built traffic model"
		bunny.model.printTypes()
		bunny.model.printMacs()
		print "starting threads: "
		
		# create list of threads
		# one thread for input and the other for output.
		# both use stdin or stdout
		workers = [StdInThread(bunny, UserName), BunnyThread(bunny, UserName)]
		
		for worker in workers:
			worker.daemon = True
			worker.start()
		
		# loop through every 3 seconds and check for dead threads
		while True:
			for worker in workers:
				if not worker.isAlive():
					bunny.killBunny()
					sys.exit()
			time.sleep(3)
		
	elif scan_chans_mode:
		for c in range(1,12):
			chan = c
			print "\nChannel: %d" % chan			
			bunny = libbunny.Bunny()
			bunny.model.printTypes()
			#bunny.model.printMacs()
			bunny.killBunny()
			
	elif ping_mode_serv:
		import struct
		
		bunny = libbunny.Bunny()
		print "Model completed, ready to play pong"
		while True:
			text = bunny.recvBunny()
			if text.find("ping") != -1:
				bunny.sendBunny(struct.pack("4sfs", "pong", time.time(), "\xff"))
				print "Pong sent"
				
		bunny.killBunny()
	
	elif ping_mode_client:
		import struct 
		
		total = 10.0
		bunny = libbunny.Bunny()
		count = 0
		avg_time = 0
		for num in range(0, int(total)):
			send_time = time.time()
			bunny.sendBunny("ping")
			text = bunny.recvBunny(2)
			if text is not False:
				#print text
				try:
					pong, mid_time, pad = struct.unpack("4sfs", text)
					
					if pong == "pong":
						in_time = time.time() - send_time
						avg_time += in_time
						count += 1
						print "got pong!"
						print "Travel time: %f\n" % (in_time)
						
				except struct.error as err:
					if text.find("ping") != -1:
						print "got ping, wtf!"
					else:
						print "bad data"
			else:
				print "ping timeout"
				time.sleep(0.1)
			#time.sleep(0.01)
		print "received:       %d packets" % (count)
		try:
			print "Percent recv'd: %02f%s" % (count * 100.0/ total, "%")
			print "Mean time:   %f" % (avg_time / count)
		except ZeroDivisionError:
			pass
		bunny.killBunny()
		
	else:
		usage()
		sys.exit()

# quick and dirty threading for the send/rec chat client mode.
class StdInThread(threading.Thread):
	"""
	
	Thread class for reading from STDIN
	
	"""
	# takes the bunny object as an argument
	def __init__(self, bunny, username):
		self.bunny = bunny
		self.username = username
		threading.Thread.__init__(self)
	def run (self):
		print "ready to read! (type: /quit to kill)"
		while True:
			input = sys.stdin.readline().strip("\n")
			if input == "/quit":
				break
			# send with UserName and a trailer to prevent the stripping of 'A's as padding
			# see the comment in the __init__() in AEScrypt
			self.bunny.sendBunny(self.username + ": " + input + "\xff")
			
class BunnyThread(threading.Thread):
	"""
	
	Thread class for reading from the bunny interface
	
	"""
	# takes the bunny object as an argument
	def __init__(self, bunny, username):
		self.bunny = bunny
		self.username = username
		threading.Thread.__init__(self)
	def run (self):
		# Standard calling should look like this:
		while True:
			text = self.bunny.recvBunny()
			# if we get our own UserName do not display it,
			# FIX THIS
			if text.split(":")[0] == self.username:
				continue
			else:
				# strip out the ending char.
				print text.rstrip("\xff")
				
		
if __name__ == "__main__":
	main()
