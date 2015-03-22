from analyzer import *
from reporters import *
from common import *
import os
import random

AnHTTP_stSearchingMarkers = 0
AnHTTP_stReadingRequestHeaders = 1
AnHTTP_stReadingRequestContent = 2
AnHTTP_stReadingResponseHeaders = 3
AnHTTP_stReadingResponseContent = 4

AnHTTP_reRequestMarker = r"^(GET|POST) .* HTTP/1.1$"
AnHTTP_reResponseMarker = r"^HTTP/1.1 [0-9]{3}"

class AnHTTP (Analyzer):

	def __init__(self, thread):
		Analyzer.__init__(self, thread)
		self.__reset()
		self.__stateHandlers = [self.__stateSearchingMarkers, 
								self.__stateReadingRequestHeaders, 
								self.__stateReadingRequestContent, 
								self.__stateReadingResponseHeaders, 
								self.__stateReadingResponseContent]

	def analyzeData(self):
		while self.__stateHandlers[self.__state](): 
			pass

	def __reset(self):
		self.__state = AnHTTP_stSearchingMarkers
		self.request = None
		self.response = None

	def _exportResponseToFile(self):

		content = self.response['content']
		if not content is None:

			if not self.request is None:
				host = self.request['headers']['Host']
				filename = self.request['url'][1:].replace("/",".")
			else:
				host = "unknown_host"
				filename = "file%06d" % int(random.random()*100000)

			path = "httpfiles/" + host 
			try:
				os.makedirs(path)
			except:
				pass

			try:
				if filename == "":
					filename = "file"
				print "Saving to ", path+"/"+filename
				f = open(path+"/"+filename,"wb")
				f.write(content)
				f.close()
			except:
				print "Could not save file!"

	def __completed(self):
		src = self._thread['src']
		dst = self._thread['dst']

		h = self.response['headers']
		if 'Content-Type' in h:
			ct = h['Content-Type']
			if CommandLine().cfg['http_export_files']:
				self._exportResponseToFile()
			
			#print "Content-Type: {0}".format(ct)

		HTTPReporter().report(src, dst, self.request, self.response)
		self.__reset()

	def __stateSearchingMarkers(self):
#		print "searching markers"
		line = self._readln()
		while not line is None:
			if self._eval(line, AnHTTP_reRequestMarker):
#				print "request marker found"
				self.request = {}
				self.request['headers'] = {}
				bs = line.find(" ")+1
				self.request['url'] = line[bs:line.find(" ", bs)]	
				self.__state = AnHTTP_stReadingRequestHeaders
				return True

			elif self._eval(line, AnHTTP_reResponseMarker):
#				print "response marker found"
				self.response = {}
				self.response['headers'] = {}
				bs = line.find(" ")+1
				self.response['statuscode'] = line[bs:line.find(" ", bs)]	
				self.__state = AnHTTP_stReadingResponseHeaders
				return True

			line = self._readln()
#		print "not enough data, will have to wait to next packet"
		return False

	def __stateReadingRequestHeaders(self):
#		print "reading request headers"
		line = self._readln()
		while not line is None:
			if line!="":
#				print "found new request header {0}".format(line)
				cpos = line.find(":")
				if cpos>0:
					self.request['headers'][line[:cpos]] = line[cpos+1:].strip()
#				else:
#					print "found something unexpected (not a request header!)"
			else:
#				print "no more request headers!"
				if ('Content-Length' in self.request['headers']) and (int(self.request['headers']['Content-Length'])>0):
#					print "this request carries content - move to content reading state"
					self.__state = AnHTTP_stReadingRequestContent 
					return True

				else:
#					print "request without extra content, move to searching markers"
					self.request['content'] = None
					self.__state = AnHTTP_stSearchingMarkers
					return True
			line = self._readln()
#		print "not enough data, will have to wait to next packet"
		return False

	def __stateReadingRequestContent(self):
#		print "trying to read request content"
		count = int(self.request['headers']['Content-Length'])	
		data = self._read(count)
		if not data is None:
#			print "request content obtained, moving to next state"
			self.request['content'] = data
			self.__state = AnHTTP_stSearchingMarkers
			return True
		else:
#			print "not enough data, will have to wait to next packet"
			return False
			

	def __stateReadingResponseHeaders(self):
#		print "reading response headers"
		line = self._readln()
		while not line is None:
			if line!="":
#				print "found new response header {0}".format(line)
				cpos = line.find(":")
				if cpos>0:
					self.response['headers'][line[:cpos]] = line[cpos+1:].strip()
#				else:
#					print "found something unexpected (not a response header!): {0}".format(line)
			else:
#				print "no more response headers!"
				if ('Content-Length' in self.response['headers']) and (int(self.response['headers']['Content-Length'])>0):
#					print "this response carries content - move to content reading state"
					self.__state = AnHTTP_stReadingResponseContent
					return True
				else:
#					print "response without extra content, move to searching markers"
					self.response['content'] = None
					self.__completed()
					return True
			line = self._readln()
#		print "not enough data, will have to wait to next packet"
		return False
	
	def __stateReadingResponseContent(self):
#		print "trying to read response content"
		count = int(self.response['headers']['Content-Length'])	
		data = self._read(count)
		if not data is None:
#			print "response content obtained, searching new markers"
			self.response['content'] = data
			self.__completed()
			return True
		else:
#			print "not enough data, will have to wait to next packet"
			return False

	def close(self):
#		print "Closing HTTP analyzer"
		pass

