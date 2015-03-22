#!/usr/bin/env python2.7
from common_methods import exit_script, display_usage, exit_error
import sys, os
import config
import config_gen
def generate_confs():
	"""
	For each section generate config files if TEMPLATE_CONFIG is present into OUTPUT_CONFIG
	Exception for HOSTAPD as it may have many variables which is not intended to be specified through TEMPLATE_CONFIG
	"""
	global_config = config_gen.get_config()
	for section in global_config.keys():
		if global_config[section].has_key('TEMPLATE_CONFIG'):
			if not global_config[section].has_key('OUTPUT_CONFIG'):
				exit_error("[ERROR] 'OUTPUT_CONFIG' not specified for '" + section + "'")
			template_file = global_config[section]['TEMPLATE_CONFIG']
			template_str = ''
			try:
				with open(template_file) as f:
					template_str = f.read()
			except:
				exit_error("[ERROR] Template File for '" + section + "', " + template_file + " does not exist") 

			for key, val in global_config[section].items():
				template_str = template_str.replace('$' + key + '$', val)

			try:
				with open(global_config[section]['OUTPUT_CONFIG'], 'wb') as f:
					print 'Writing', f.name, '...'
					f.write(template_str)
			except:
				exit_error("[ERROR] Failed to open output_config '" + global_config[section]['OUTPUT_CONFIG'] + "' in write mode")
		elif section == 'HOSTAPD':
			write_hostapd_conf(global_config)
			
def write_hostapd_conf(global_config):
	config_output = global_config['HOSTAPD']['OUTPUT_CONFIG']
	print 'Writing', config_output, '...'
	try:
		with open(config_output, 'w') as f:
			for key, val in global_config['HOSTAPD'].items():
				if key not in config.special_options:
					f.write( key + '=' + val + '\n' )
	except:
		exit_error('[ERROR] Failed to open ' + config_output + ' in write mode')
def test():
	config_gen.init()
	generate_confs()

if __name__ == '__main__':
	test()
