#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    bunny.py
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


import threading, Queue, binascii

from AEScrypt import *
from SendRec import *
from Templates import *
from TrafficModel import *
from config import *


# So this is the heart and soul of bunny and also the biggest mess in the code base.
#  if anyone wants to look over my use of threads, queue and deques it would be lovely
#  to get some feedback and if anyone thinks there is a way to speed this up it would help.

class Bunny:
	"""
	
	High level send and receive for wrapping all the lower-level functions of bunny in paranoid mode.
	
	"""
	
	def __init__(self):
		"""
		
		Setup and build the bunny model and starts the read_packet_thread()
		
		"""
		
		self.inandout = SendRec()
		self.cryptor = AEScrypt()
		self.model = TrafficModel()
		
		# each item should be an full bunny message that can be passed to the .decrypt() method
		# TODO: put a upper bound of number of messages or a cleanup thread to clear out old messages
		#  if not consumed.
		self.msg_queue = Queue.LifoQueue()
		
		# The out queue is a FiFo Queue because it maintaines the ordering of the bunny data
		#  format: [data, Bool (relay or not)]
		self.out_queue = Queue.Queue()
		
		# The Deque is used because it is a thread safe iterable that can be filled with 'seen'
		# messages between the send and recv threads. 
		self.msg_deque = []
		
		# init the threads and name them
		self.workers = [BunnyReadThread(self.msg_queue, self.out_queue, self.inandout, self.model, self.cryptor), \
			BroadCaster(self.out_queue, self.inandout, self.model)]
		self.workers[0].name = "BunnyReadThread"
		self.workers[1].name = "BroadCasterThread"
		
		# spin up the threads
		for worker in self.workers:
			worker.daemon = True
			worker.start()
		
		#TODO: can I add a 'isAlive()' checking loop here?
		
	def sendBunny(self, packet):
		"""
		
		Send a Bunny (paranoid) packet
		
		"""
		packet = self.cryptor.encrypt(packet)
		# Prepend the length of the packet as the first two bytes.
		#  This allows for Bunny to know when to stop reading in packets.
		size = struct.pack("H", len(packet))
		packet = "%s%s" % (size, packet)
		
		self.msg_deque.append([packet, time.time()])
		self.out_queue.put([packet, False])
		
	def recvBunny(self, timer=False):
		"""
		
		Grab the next bunny message in the queue and decrypt it and return the plaintext message
		
		Arg: timer
			If not false, bunny will timeout in the number of seconds in timer
		
		Returns:
			Decrypted bunny message or if timedout, False
		
		"""
		# this is looped just so if the message has been seen we can come back and keep trying.
		while True:
			relay = False
			if timer:
				try:
					data = self.msg_queue.get(True, timer)
				except Queue.Empty:
					return False
			else:
				data = self.msg_queue.get()
			
			# check if the message has already been seen
			#  TODO: move this whole thing to a new thread
			cur_time = time.time()
			for message in self.msg_deque:
				if message[0] == data:
					if DEBUG:
						print "Already seen message, not sending to user"
					relay = True
				# remove old known messages
				if cur_time - message[1] > 60:
					self.msg_deque.remove(message)
					
			if relay == True:
				continue
			else:
				self.out_queue.put([data, True])
				self.msg_deque.append([data, time.time()])
				
				# remove the size data:
				data = data[2:]
				plaintext = self.cryptor.decrypt(data)
				if plaintext == False:
					continue
				else:
					return plaintext
				
	def killBunny(self):
		for worker in self.workers:
			worker.kill()

class BunnyReadThread(threading.Thread):

	def __init__(self, queue, out_queue, ioObj, model, cryptor):
		self.msg_queue = queue
		self.out_queue = out_queue
		self.inandout = ioObj
		self.model = model
		self.cryptor = cryptor
		
		self.running = True
		threading.Thread.__init__(self)

	def run(self):
		blockget = False
		decoded = ""
		
		while self.running:
			# declare / clear the type array.
			type = []
	
			encoded = self.inandout.recPacket_timeout(self.model.FCS)
				#TIMING
				#start_t = time.time()
			if encoded is False:
				blockget = False
				decoded = ""
				continue
			
			if DEBUG:
				print "\nHit packet"
				print "Type: %s\t Raw: %s" % (binascii.hexlify(encoded[0:1]), self.model.rawToType(encoded[0:1]))
			
			for entry in self.model.type_ranges:
				if entry[0] == encoded[0:1]:
					if entry[2].injectable > 0:
						# check so that the injectable length is over 0
						type = entry
						break
			
			if len(type) < 2:
				if DEBUG:
					print "Packet type not in templates"
				
				entry = self.model.insertNewTemplate(encoded)
				if entry is not False:
					if DEBUG:
						print "successfuly inserted template"
					self.model.type_ranges.append(entry)
					type = entry
				else:
					if DEBUG:
						print "Packet type not implemented"
					continue
			
			# decode the bunny packet
			temp = type[2].decode(encoded)

			if temp is False:
				if DEBUG:
					print "decoding fail"
				continue
			else:
				if DEBUG:
					print "CypherText: " + binascii.hexlify(temp)
				
				if blockget == False:
					pack_len, = struct.unpack("H", temp[0:2])

					if DEBUG:
						print "size: " + str(pack_len)
					
					blockget = True
					decoded = "%s%s" % (decoded, temp)
					decoded_len = len(decoded)
				elif decoded_len < pack_len:
					decoded = "%s%s" % (decoded, temp)
					decoded_len = len(decoded)
				if decoded_len >= pack_len:
					if DEBUG:
						print "Adding message to Queues"
					self.msg_queue.put(decoded)
					
					#TIMING
					#print "recv time: %f" % (time.time() - start_t)
					
					# clean up for the next loop
					blockget = False
					decoded = ""
	def kill(self):
		self.running = False
		self.inandout.close()
						
class BroadCaster(threading.Thread):
	
	def __init__(self, queue, ioObj, model):
		self.out_queue = queue
		self.inandout = ioObj
		self.model = model
		
		self.seen_chunks = []

		self.running = True
		threading.Thread.__init__(self)
	
	def run(self):
		while self.running:
			relay = True
			
			element = self.out_queue.get()
			#TIMING
			#start_t = time.time()
			
			# sleep here if the packet is a relay packet, this prevents corruption by a 
			#	node in between two machines that are in range.  
			#	TODO: This value needs to be modified and played with.  
			if element[1] is True:
				time.sleep(0.01)
			packet = element[0]
			
			if DEBUG:
				print "CypherText: " + binascii.hexlify(packet)
				blocks, = struct.unpack("H", packet[0:2])
				print "size: " + str(blocks)
			
			
			while ( len(packet) != 0 ):
				entry = self.model.getEntry()
				outpacket = entry[2].makePacket(packet[:entry[2].injectable])
				if DEBUG:
					print "Sending with: %s" % self.model.rawToType(entry[0])
					print "length: " + str(len(outpacket))

				packet = packet[entry[2].injectable:]
				self.inandout.sendPacket(outpacket)
			#TIMING
			#print "Send time: " + str(time.time() - start_t)
	def kill(self):
		self.running = False
		self.inandout.close()