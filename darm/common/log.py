from common import *

# Colors
RED='\033[91m'
YEL='\033[93m'
GRE='\033[92m'
BLU='\033[94m'
PUR='\033[95m'
CYA='\033[96m'
END='\033[0m'

class Log:

	def __call__(self):
		return self

	def __init__(self):
		pass

	def write(self, msg, verbosity=1, important=0):
		
		color = RED if important else END
		
		if verbosity <= CommandLine().cfg['verbosity']:
			print "{1}{0}{2}".format(msg, color, END)

Log = Log()
