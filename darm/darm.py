#! /usr/bin/env python
from unpackers import *
from sources import *
from common import *

class darm:

	def __init__(self):
		cfg = CommandLine().cfg
		self.__source = Source()
		unpacker = Unpackers().getRoot()
		self.__source.setUnpacker(unpacker)

	def run(self):	
		cfg = CommandLine().cfg
		if 'dumpfile' in cfg:
			self.__source.dumpfile = cfg['dumpfile']	

		if cfg['method'] == "file":
			print "Reading from '{0}', press Ctrl+C to stop".format(cfg['filename'])
			self.__source.runFromFile(cfg['filename'])

		elif cfg['method'] == "live":
			print "Capturing live from {0}, press Ctrl+C to stop".format(cfg['interface'])
			self.__source.runLive(cfg['interface'])

if __name__ == "__main__":
	darm().run()
