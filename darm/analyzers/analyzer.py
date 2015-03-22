import re

class Analyzer:

	def __init__(self, thread):
		self._thread = thread
		self.__cursor = 0

	def _readUntil(self, pattern):
		data = self._thread['data']
		pos = data.find(pattern, self.__cursor)
		if (pos<0):
			return None
		else:
			line = data[self.__cursor:pos]
			self.__cursor = pos+len(pattern)
			return line	

	def _readln(self):
		return self._readUntil("\x0D\x0A")

	def _read(self):
		data = self._thread['data']
		c = self.__cursor
		self.__cursor = len(data)-1
		return data[c:]

	def _read(self, count):
#		print "reading {0} bytes, cursor is in position {1}".format(count, self.__cursor)
		data = self._thread['data']
		c = self.__cursor
		r = len(data)-c
		if r<count:
#			print "not enough packet info"
			return None
		else:
			self.__cursor += count
#			print "reading data[{0}:{1}]".format(c,self.__cursor)
			return data[c:self.__cursor]

	def _eval(self, pattern, regstr):
		regex = re.compile(regstr)
		return False if regex.search(pattern) is None else True 

	def close(self):
		pass


