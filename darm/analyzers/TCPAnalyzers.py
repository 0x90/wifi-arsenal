from anHTTP import *

try: TCPAnalyzers
except:
	class TCPAnalyzers:

		def __call__(self):
			return self

		def __init__(self):
			self.__threadAnalyzers = {}

		def __createAnalyzers(self, thread):
			analyzers = [AnHTTP(thread)]
			return analyzers

		def __sendDataToAnalyzers(self, thread):
			seq = thread['seq']
			analyzers = self.__threadAnalyzers[seq]
			for analyzer in analyzers:
				analyzer.analyzeData()

		def analyzeData(self, thread):
			seq = thread['seq']
			if not seq in self.__threadAnalyzers:
				self.__threadAnalyzers[seq] = self.__createAnalyzers(thread)
			self.__sendDataToAnalyzers(thread)

		def closeAnalyzers(self, thread):
			seq = thread['seq']
			if seq in self.__threadAnalyzers:
				for analyzer in self.__threadAnalyzers[seq]:			
					analyzer.close()

	TCPAnalyzers = TCPAnalyzers()
