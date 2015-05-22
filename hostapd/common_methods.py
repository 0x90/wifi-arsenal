import sys
import app_info
from config import bcolors
def exit_error(msg, err_no = 0):
	print bcolors.FAIL, msg, bcolors.ENDC
	if err_no == 1:
		display_usage()
	sys.exit(1)
def exit_script():
	sys.exit()

def display_usage():
	print app_info.name,'-', app_info.description
	print '   Version :', app_info.version
	print '   by', app_info.author
	print '   email:', app_info.email
	print '   github page:',app_info.github
	print
	print 'Usage :'
	print '   hostapd.py [action] [<options>...]'
	print
	print 'Following actions are currently supported:'
	print '   start'
	print '   stop'
	print '   restart'
	print '   config'
	print '   help'
	print
	print 'Usage for action config:'
	print '   hostapd.py config list                     - list all attributes with values'
	print '   hostapd.py config attrib_name              - shows the value for attrib_name, if set'
	print '   hostapd.py config attrib_name attrib_val   - modifies the value of attrib_name to attrib_val'
