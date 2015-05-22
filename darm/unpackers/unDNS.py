from unpacker import *
from reporters import *

class UnDNS (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

		# original
		#self.__TYPES = ['A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT']

		# sebas
		self.__TYPES = ['A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT','RP','AFSDB','X25','ISDN','RT','NSAP','NSAP-PTR','SIG','KEY','PX','GPOS','AAAA','LOC','NXT','EID','NIMLOC','SRV','ATMA','NAPTR','KX','CERT','A6','DNAME','SINK','OPT','APL','DS','SSHFP','IPSECKEY','RRSIG','NSEC','DNSKEY','DHCID','NSEC3','NSEC3PARAM','Unassigned','HIP','NINFO','RKEY','TALINK','CDS','Unassigned','SPF','UINFO','UID','GID','UNSPEC','Unassigned','TKEY','TSIG','IXFR','AXFR','MAILB','MAILA','*','URI','CAA','Unassigned','TA','DLV','Unassigned']


		"""
		List to understand what they are
		Registry:
		TYPE         Value and meaning                              Reference
		-----------  ---------------------------------------------  ---------
		A            1 a host address                               [RFC 1035]
		NS           2 an authoritative name server                 [RFC 1035]
		MD           3 a mail destination (OBSOLETE - use MX)       [RFC 1035]
		MF           4 a mail forwarder (OBSOLETE - use MX)         [RFC 1035]
		CNAME        5 the canonical name for an alias              [RFC 1035]
		SOA          6 marks the start of a zone of authority       [RFC 1035]
		MB           7 a mailbox domain name (EXPERIMENTAL)         [RFC 1035]
		MG           8 a mail group member (EXPERIMENTAL)           [RFC 1035]
		MR           9 a mail rename domain name (EXPERIMENTAL)     [RFC 1035]
		NULL         10 a null RR (EXPERIMENTAL)                    [RFC 1035]
		WKS          11 a well known service description            [RFC 1035]
		PTR          12 a domain name pointer                       [RFC 1035]
		HINFO        13 host information                            [RFC 1035]
		MINFO        14 mailbox or mail list information            [RFC 1035]
		MX           15 mail exchange                               [RFC 1035]
		TXT          16 text strings                                [RFC 1035]
		RP           17 for Responsible Person                      [RFC 1183]
		AFSDB        18 for AFS Data Base location                  [RFC 1183][RFC 5864]
		X25          19 for X.25 PSDN address                       [RFC 1183]
		ISDN         20 for ISDN address                            [RFC 1183]
		RT           21 for Route Through                           [RFC 1183]
		NSAP         22 for NSAP address, NSAP style A record       [RFC 1706]
		NSAP-PTR     23 for domain name pointer, NSAP style         [RFC 1348][RFC 1637][RFC 1706]
		SIG          24 for security signature                      [RFC 4034][RFC 3755][RFC 2535][RFC 2536][RFC 2537][RFC 2931][RFC 3110][RFC 3008]
		KEY          25 for security key                            [RFC 4034][RFC 3755][RFC 2535][RFC 2536][RFC 2537][RFC 2539][RFC 3008][RFC 3110]
		PX           26 X.400 mail mapping information              [RFC 2163]
		GPOS         27 Geographical Position                       [RFC 1712]
		AAAA         28 IP6 Address                                 [RFC 3596]
		LOC          29 Location Information                        [RFC 1876]
		NXT          30 Next Domain (OBSOLETE)                      [RFC 3755][RFC 2535]
		EID          31 Endpoint Identifier                         [Patton][Patton1995]
		NIMLOC       32 Nimrod Locator                              [Patton][Patton1995]
		SRV          33 Server Selection                            [RFC 2782]
		ATMA         34 ATM Address                                 [ATMDOC]
		NAPTR        35 Naming Authority Pointer                    [RFC 2915][RFC 2168][RFC 3403]
		KX           36 Key Exchanger                               [RFC 2230]
		CERT         37 CERT                                        [RFC 4398]
		A6           38 A6 (OBSOLETE - use AAAA)                    [RFC 3226][RFC 2874][RFC-jiang-a6-to-historic-00.txt]
		DNAME        39 DNAME                                       [RFC 2672]
		SINK         40 SINK                                        [Eastlake][Eastlake2002]
		OPT          41 OPT                                         [RFC 2671][RFC 3225]
		APL          42 APL                                         [RFC 3123]
		DS           43 Delegation Signer                           [RFC 4034][RFC 3658]
		SSHFP        44 SSH Key Fingerprint                         [RFC 4255]
		IPSECKEY     45 IPSECKEY                                    [RFC 4025]
		RRSIG        46 RRSIG                                       [RFC 4034][RFC 3755]
		NSEC         47 NSEC                                        [RFC 4034][RFC 3755]
		DNSKEY       48 DNSKEY                                      [RFC 4034][RFC 3755]
		DHCID        49 DHCID                                       [RFC 4701]
		NSEC3        50 NSEC3                                       [RFC 5155]
		NSEC3PARAM   51 NSEC3PARAM                                  [RFC 5155]
		Unassigned   52-54
		HIP          55 Host Identity Protocol                      [RFC 5205]
		NINFO        56 NINFO                                       [Reid]
		RKEY         57 RKEY                                        [Reid]
		TALINK       58 Trust Anchor LINK                           [Wijngaards]
		CDS          59 Child DS                                    [Barwood]
		Unassigned   60-98
		SPF          99                                             [RFC 4408]
		UINFO        100                                            [IANA-Reserved]
		UID          101                                            [IANA-Reserved]
		GID          102                                            [IANA-Reserved]
		UNSPEC       103                                            [IANA-Reserved]
		Unassigned   104-248
		TKEY         249 Transaction Key                            [RFC 2930]
		TSIG         250 Transaction Signature                      [RFC 2845]
		IXFR         251 incremental transfer                       [RFC 1995]
		AXFR         252 transfer of an entire zone                 [RFC 1035][RFC 5936]
		MAILB        253 mailbox-related RRs (MB, MG or MR)         [RFC 1035]
		MAILA        254 mail agent RRs (OBSOLETE - see MX)         [RFC 1035]
		*            255 A request for all records                  [RFC 1035]
		URI          256 URI                                        [Faltstrom]
		CAA          257 Certification Authority Authorization      [Hallam-Baker]
		Unassigned   258-32767
		TA           32768   DNSSEC Trust Authorities               [Weiler]           2005-12-13
		DLV          32769   DNSSEC Lookaside Validation            [RFC 4431]
		Unassigned   32770-65279  
		Private use  65280-65534
		Reserved     65535 
		"""

		# original
		#self.__QTYPES = ['AXFR', 'MAILB', 'MAILA', '*']
		#self.__CLASSES = ['IN','CS','CH','HS']
		#self.__EXTTYPES = ['AAAA']

		# by sebas
		self.__CLASSES = ['IN','CS','CH','HS','ANY']
		
	def __str__(self): 
		return "DNS unpacker"

	def __ttlToString(self, secs):
		hours, secs = divmod(secs, 3600)
		minutes, secs = divmod(secs, 60)
		response = []
		response += ["{0} hours".format(hours)] if hours>0 else ""
		response += ["{0} minutes".format(minutes)] if minutes>0 else ""
		response += ["{0} seconds".format(secs)] if secs>0 else ""
		return ", ".join(response) if len(response)>0 else "None"

	def __getDomainString(self, idx, p):
		subdomains = []
		c = ord(p[idx])
		ptr = 0
		while c>0:
			if c & 0xC0:
				if ptr==0:
					ptr = idx
				idx = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0]) & 0x3FFF
				c = ord(p[idx])		
			idx += 1
			subdomains += [p[idx:idx+c]]
			idx += c	
			c = ord(p[idx])
		
		idx = ptr+2 if ptr>0 else idx+1
		domain = ".".join(subdomains)
		return (idx, domain)

	def __getResourceRecord(self, idx, p):
		idx, RRname = self.__getDomainString(idx, p)
		RRtype = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0])
		RRclass = socket.ntohs(struct.unpack('H',p[idx+2:idx+4])[0])
		RRttl = socket.ntohl(struct.unpack('I',p[idx+4:idx+8])[0])
		RRdatalen = socket.ntohs(struct.unpack('H',p[idx+8:idx+10])[0])
		idx += 10

		RRdata = p[idx:idx+RRdatalen]
		if RRtype == 1:
			# type A
			RRdata = socket.inet_ntoa(RRdata)
		elif RRtype == 5:
			# type CNAME
			RRdata = self.__getDomainString(idx, p)[1]
		idx += RRdatalen

		RRtype = self.__TYPES[RRtype-1]
		RRclass = self.__CLASSES[RRclass-1]
		RRttl = self.__ttlToString(RRttl)
		RR = { 'type': RRtype, 'class': RRclass, 'ttl': RRttl, 'data': RRdata }
		return (idx, RR)

	def __getQuestionRecord(self, idx, p):
		idx, domain = self.__getDomainString(12, p)
		qtype = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0])

		# deleted by sebas
		#if qtype<0x001C:
			#qtype = self.__TYPES[qtype-1]
		#elif qtype<252: 
			#qtype = self.__EXTTYPES[qtype-0x001C]  
		#else:
			#qtype = self.__QTYPES[qtype-252]

		# sebas
		if qtype:
			qtype = self.__TYPES[qtype-1]
		# end sebas

		qclass = socket.ntohs(struct.unpack('H',p[idx+2:idx+4])[0])
		qclass = self.__CLASSES[qclass-1] if qclass<>255 else "*"
		idx += 4
		question = { 'domain': domain, 'type': qtype, 'class': qclass }
		return (idx, question)

	def validate(self, packet):
		isValid = False
		try:
			isValid = (packet['udp']['dst'] == 53) or (packet['udp']['src'] == 53)
		except:
			pass
		return isValid

	def process(self, packet):
		p = packet['payload']
		d={}
		d['transaction-id'] = socket.ntohs(struct.unpack('H',p[0:2])[0])
		d['flags'] = socket.ntohs(struct.unpack('H',p[2:4])[0])
		d['type'] = "response" if d['flags'] & 0x8000 else "query"

		questionRRs = socket.ntohs(struct.unpack('H',p[4:6])[0])
		answerRRs = socket.ntohs(struct.unpack('H',p[6:8])[0])
		authorityRRs = socket.ntohs(struct.unpack('H',p[8:10])[0])
		additionalRRs = socket.ntohs(struct.unpack('H',p[10:12])[0])

		d['questions'] = []
		for i in range(questionRRs):
			idx, question = self.__getQuestionRecord(12, p)
			d['questions'] += [question]

		d['answers'] = []
		for i in range(answerRRs):
			idx, rr = self.__getResourceRecord(idx, p)
			d['answers'] += [rr]			 			

		d['authority'] = []
		for i in range(authorityRRs):
			idx, rr = self.__getResourceRecord(idx, p)
			d['authority'] += [rr]			 			

		d['additional'] = []
		for i in range(additionalRRs):
			idx, rr = self.__getResourceRecord(idx, p)
			d['additional'] += [rr]			 			
	
		packet['top'] = "dns"
		packet['path'] += ".dns"
		packet['dns'] = d
		packet['payload'] = None

		DNSReporter().report(packet)
				
	def close(self):
		Unpacker.close(self)

