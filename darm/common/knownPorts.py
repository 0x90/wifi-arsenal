
try: KnownPorts
except:
	class KnownPorts:

		def __call__(self):
			return self

		def __init__(self):
			tcp = {}
			tcp[20] = 'ftpdata'
			tcp[21] = 'ftp'
			tcp[22] = 'ssh'
			tcp[23] = 'telnet'
			tcp[25] = 'smtp'
			tcp[53] = 'dns'
			tcp[80] = 'http'
			tcp[115] = 'sftp'
			tcp[143] = 'imap'
			tcp[443] = 'https'
			tcp[989] = 'ftpsdata'
			tcp[990] = 'ftps'
			tcp[3306] = 'mysql'
			self.__TCPPorts = tcp

		def tcp(self, port):
			try:
				return self.__TCPPorts[int(port)]
			except:
				return port

KnownPorts = KnownPorts()
