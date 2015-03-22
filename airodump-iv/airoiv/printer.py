"""
Define a singleton that handles basic output
"""
import sys
import traceback

class Printer:
	"""A class for printing messages that respects verbosity levels"""
	verbose_level = 0

	@staticmethod
	def verbose(message, verbose_level=1):
		"""Print a message only if it is within an acceptabe verbosity level"""
		if Printer.verbose_level >= verbose_level:
			sys.stdout.write(message)
			sys.stdout.write('\n')

	@staticmethod
	def write(message):
		"""Write a message to stdout"""
		sys.stdout.write(message)
		sys.stdout.write('\n')

	@staticmethod
	def error(message):
		"""Write a message to stderr"""
		sys.stderr.write(message)
		sys.stderr.write('\n')

	@staticmethod
	def exception(e):
		"""Write a summary of an exception with a stack trace"""
		Printer.error(repr(e))
		traceback.print_exc(file=sys.stderr)


