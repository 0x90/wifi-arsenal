#!/usr/bin/env python2.7
import subprocess, config, sys, config_gen, shlex, os, errno
from time import sleep
from common_methods import exit_script, exit_error
from config_hostapd import generate_confs

def make_dirs(conf):
	if conf.has_key('LOGFILE'):
		dirname = os.path.dirname(conf['LOGFILE'])
		try:
			os.makedirs(dirname)
		except OSError as exc:
			if exc.errno != errno.EEXIST:
				raise

def start_hostapd():
	generate_confs()
	conf = config_gen.get_config()
	env_tups = [(section+'_'+key, val) for section in conf.keys() for key, val in conf[section].items()]
	env_dict = dict(os.environ.items() + env_tups)
	
	print 'Starting...'
	for section in config.script_order:
		if conf[section].has_key('SCRIPT'):
			make_dirs(conf[section])
			print 'Executing %s for [%s]...' % (conf[section]['SCRIPT'], section),
			ret = subprocess.call(conf[section]['SCRIPT'], env=env_dict)
			if ret == 0:
				print 'Done!'
			else:
				print 'Failed!'
				exit_error('[ERROR] Failed to initiate [%s], check log file %s' % (section, conf[section]['LOGFILE']))
		sleep(1)
		


def stop_hostapd():
	conf = config_gen.get_config()
	env_tups = [(section+'_'+key, val) for section in conf.keys() for key, val in conf[section].items()]
	env_dict = dict(os.environ.items() + env_tups)

	print 'Stopping...'
	for section in config.script_order[::-1]:
		if conf[section].has_key('EXIT_SCRIPT'):
			make_dirs(conf[section])
			print 'Executing %s for [%s]...' % (conf[section]['EXIT_SCRIPT'], section),
			ret = subprocess.call(conf[section]['EXIT_SCRIPT'], env=env_dict)
			if ret == 0:
				print 'Done!'
			else:
				print 'Failed!'
				exit_error('[ERROR] Failed to exit [%s], check log file %s' % (section, conf[section]['LOGFILE']))
def restart_hostapd():
	stop_hostapd()
	# Workaround for issues with dhcpd
	sleep(2)

	start_hostapd()
