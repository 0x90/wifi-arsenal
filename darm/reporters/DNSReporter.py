from reporters.reporter import *
import time
import re

try: DNSReporter
except:
	
	class DNSReporter (Reporter):

		def __init__(self):
			self.__queries = {}
			
			self.__ignoredDomains = []
			self.__importantDomains = ["(.)*(facebook|fbcdn)\.(com|net)",
									   "(.)*google\.com",
									   "(.)*hotmail\.com",
									   "(.)*yahoo\.com",]

		def __call__(self):
			return self

		def _validate(self, packet):
			valid = False
			if Reporter._validate(self):
				valid = packet['dns']['type'] == "query"
			return valid

		def __addDomainRequestEntry(self, who, when, what):
			
			q = self.__queries
			if not who in q:
				q[who] = { "count": 1, "what": [what] }
			else:
				q[who]["count"] += 1
				if not what in q[who]["what"]: 
					q[who]["what"].append(what)
			
			text = "({2}) {0} is asking the IP address of {1}".format(who,what,when)
			Log.write(text, 2)

		def __isDomainImportant(self, domain):
			for exp in self.__importantDomains:
				regex = re.compile(exp)
				match = regex.search(domain)
				if match:
					return True
			return False

		def report(self, packet):
			if self._validate(packet):
				src = packet['ip']['src']
				timestamp = packet['raw']['timestamp']
				for question in packet['dns']['questions']:
					
					ts = time.localtime(timestamp[0])
					timeAsString = time.asctime(ts)
					self.__addDomainRequestEntry(src, timeAsString, question['domain'])
					

		def summaryReport(self):
			total = 0
			q = self.__queries
			if len(q)>0:
				Log.write("[+] DNS Summary:",1)
				for key in q.keys():
					Log.write("[+] {}  ({} DNS Requests)".format(key,q[key]["count"]),1)
					total = total + q[key]["count"]
					for domain in q[key]["what"]:
						Log.write("  - {0}".format(domain), 
								verbosity=1, 
								important=self.__isDomainImportant(domain) )
						
				Log.write("\n[+] Total IP address: {}".format(len(q.keys())),1)
				Log.write("[+] Total requests: {}".format(total),1)
				Log.write("\n-- End DNS Summary",1)					


DNSReporter = DNSReporter()
		