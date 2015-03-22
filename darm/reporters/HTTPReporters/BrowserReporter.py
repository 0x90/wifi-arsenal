import re
from reporters.reporter import *

BrowserREs = [
	'MSIE [0-9]\.[0-9]'
	,'Chrome/[0-9]+(\.[0-9]+)*'
	,'BlackBerry[0-9]*/[0-9]+(\.[0-9]+)*'
	,'Firefox/[0-9]+(\.[0-9]+)*'
	,'Twitter/[0-9]+(\.[0-9]+)*'
	,'Sparrow/[0-9]+(\.[0-9]+)*'
	,'Skype(/[0-9]+(\.[0-9]+)*){0,1}'
	,'Prey/[0-9]+(\.[0-9]+)*'
	,'Macintosh.*Safari/[0-9]+(\.[0-9]+)*$'
]

try: BrowserReporter
except:
	class BrowserReporter (Reporter):

		def __call__(self):
			return self

		def __init__(self):
			self.__knownBrowsers = {}

		def _agentToBrowser(self, agent):
			for exp in BrowserREs:
				regex = re.compile(exp)
				match = regex.search(agent)
				if match:
					return match.group(0)
			return None

		def _validate(self, request):
			valid = Reporter._validate(self) and (not request is None) and ('User-Agent' in request['headers'])
			return valid

		def report(self, src, dst, request, response):
			if self._validate(request):
				agent = request['headers']['User-Agent']
				browser = self._agentToBrowser(agent)
				if not browser is None:
					if not src in self.__knownBrowsers:
						self.__knownBrowsers[src] = []
					if not browser in self.__knownBrowsers[src]:
						print "{0} is using {1}".format(src, browser) 
						self.__knownBrowsers[src] += [browser]
#					else:
#						print "Unknown user agent: {0}".format(agent)

BrowserReporter = BrowserReporter()

