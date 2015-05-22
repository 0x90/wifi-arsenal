#!/usr/bin/env python2.7
import sys
import config_gen
from HPS import start_hostapd, stop_hostapd, restart_hostapd
from config_hostapd import generate_confs
from common_methods import exit_script, display_usage

def main():
	"""
	The starting point
	"""
	config_gen.init()
	actions = { 'start' : start_hostapd,
			'stop' : stop_hostapd,
			'restart' : restart_hostapd,
			'config' : config_gen.config_cli,
			'help' : display_usage,
			'-h' : display_usage,
			}

	if len(sys.argv)>1 and sys.argv[1] in actions:
		actions[sys.argv[1]]()
	else:
		print '[ERROR] Invalid Argument\n'
		display_usage()
	exit_script()

if __name__ == '__main__':
	main()
