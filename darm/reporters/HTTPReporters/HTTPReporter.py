from reporters.reporter import *
from GoogleReporter import *
from BrowserReporter import *

try: HTTPReporter
except:
	class HTTPReporter (Reporter):

		def __call__(self):
			return self

		def __init__(self):
			Reporter.__init__(self)	
			self.__reporters = [GoogleReporter(), 
								BrowserReporter()]

		def report(self, src, dst, request, response):
			if self._validate():
				for reporter in self.__reporters:
					apply(reporter.report, (src, dst, request, response)) 

HTTPReporter = HTTPReporter()
