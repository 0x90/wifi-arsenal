import urllib
from common import *

class Reporter:

	def __init__(self):
		pass

	def _urldecode(self, str):
		return urllib.unquote(str).replace("+", " ")

	def _validate(self):
		return CommandLine().cfg['reporters_enabled']

	def summaryReport(self):
		return ""