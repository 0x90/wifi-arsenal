import sys
import shlex

try: CommandLine
except:
	class CommandLine:

		def __call__(self):
			return self

		def __init__(self):
			self.__showBanner()
			try:
				self.__initcfg()
				self.__args = shlex.split(" ".join(sys.argv[1:]))
				self.__args.reverse()
				arg = self.__getNextArgument()				
				while not arg is None:
					self.__setArgument(arg)
					arg = self.__getNextArgument()

			except Exception as ex:
				self.__paramError("unhandled parsing error - {0}".format(ex))
			else:
				self.__checkMandatoryArgs()			

		def __getNextArgument(self):
			if len(self.__args)>0:			
				arg = [self.__args.pop()]
				while len(self.__args)>0 and self.__args[len(self.__args)-1][0]!="-":
					arg += [self.__args.pop()]
				return arg
			else:
				return None

		def __showBanner(self):
			print "darm - intelligent network sniffer for the masses"

		def __initcfg(self):
			self.cfg = {}
			self.cfg['verbosity'] = 1
			self.cfg['tcp_dumpthreads'] = False
			self.cfg['reporters_enabled'] = False
			self.cfg['http_export_files'] = False

		def __setArgument(self, arg):
			if arg[0]=="-i":
				if 'method' in self.cfg: self.__paramError("specify one input source only")
				self.cfg['method'] = 'live'
				self.cfg['interface'] = arg[1]

			elif arg[0]=="-r":
				if 'method' in self.cfg: self.__paramError("specify one input source only")
				self.cfg['method'] = 'file'
				self.cfg['filename'] = arg[1]

			elif arg[0]=="-w":
				self.cfg['dumpfile'] = arg[1]

			elif arg[0]=="-t":
				self.cfg['tcp_dumpthreads'] = True

			elif arg[0]=="-a":
				self.cfg['reporters_enabled'] = True

			elif arg[0]=="-f":
				self.cfg['http_export_files'] = True

			elif arg[0]=="-v":
				try:
					value = int(arg[1])
				except:
					self.__paramError("verbosity level must be a number")
				else:			
					if value<0 or value>3	: self.__paramError("verbosity level must be between 0 and 3")
					print "Verbosity set to {0}".format(value)
					self.cfg['verbosity'] = value

			else:
				self.__paramError("parameter {0} not recognized".format(arg[0])) 

		def __checkMandatoryArgs(self):
			if not 'method' in self.cfg: self.__paramError("specify input method")

		def __paramError(self, msg):
			print "Invalid arguments: {0}".format(msg)
			print "USAGE: ./darm.py option value option value ..."
			print " METHOD: determines source of input data. Mandatory."
			print "  -i (interface)   live interface"
			print "  -r (filename)    capture file"
			print " OUTPUT: Dump input data to capture file."
			print "  -w (filename)    dump filename"
			print "  -t               save TCP threads to folder"
			print "  -f               dump files transferred via HTTP to current folder"
			print " VERBOSITY: how much detail you want about ongoing tasks."
			print "  -a               report current computer activity in layman's terms"
			print "  -v (level)       verbosity level number. Must be between 0 and 3. Default is 1."
			sys.exit(-1)

CommandLine = CommandLine()
