import os
prefix = os.path.dirname(os.path.realpath(__file__))
os.chdir(prefix)
# File locations
file_cfg = 'py_hostapd.cfg'

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

# config_template specifies the attribute type, default value and available choices
# type 0 means that the attribute doesn't have any limited choices as their values
# type 1 means that the attribute value should be from one of the values specified by 'choices' list
hostapd_defaults = {
		'OUTPUT_CONFIG' : {'type' : 0, 'default' : '/etc/py_hostapd.conf'},
		'SCRIPT' : {'type' : 0, 'default' : 'scripts/hostapd'},
		'EXIT_SCRIPT': {'type' : 0, 'default' : 'scripts/hostapd_exit'},
		'interface' : {'type' : 0, 'default' : 'wlan0'},
		'driver' : {'type' : 0, 'default' : 'nl80211'},
		'ssid' : {'type' : 0, 'default' : 'test'},
		'hw_mode' : {'type' : 1, 'default' : 'g', 'choices' : ['a','b','g']},
		'channel' : {'type' : 1, 'default' : '6', 'choices' : [str(x) for x in range(1,12)]},
		'macaddr_acl' : {'type' : 1, 'default' : '0', 'choices' : ['0','1','2']},
		'auth_algs' : {'type' : 1, 'default' : '1', 'choices' : ['1','2','3']},
		'ignore_broadcast_ssid' : {'type' : 1, 'default' : '0', 'choices' : ['0','1','2']},
		'wpa' : {'type' : 1, 'default' : '3', 'choices' : ['1','2','3']},
		'wpa_passphrase' : {'type' : 0, 'default' : 'foobar123'},
		'wpa_key_mgmt' : {'type' : 1, 'default' : 'WPA-PSK', 'choices' : ['WPA-PSK','WPA-EAP','WPA-PSK WPA-EAP']},
		'wpa_pairwise' : {'type' : 1, 'default' : 'TKIP', 'choices' : ['TKIP','CCMP']},
		'rsn_pairwise' : {'type' : 1, 'default' : 'CCMP', 'choices' : ['TKIP','CCMP']},
		'LOGFILE' : {'type' : 0, 'default' : 'logs/hostapd'},
		}


# general defaults
general_defaults = {
	'SCRIPT' : 'scripts/init',
	'in' : 'wlan0',
	'out' : 'eth0',
	'ip_wlan' : '10.0.0.1',
	'netmask' : '255.255.255.0',
	'LOGFILE' : 'logs/init',
}

# dhcp defaults
dhcp_defaults = {
	'OUTPUT_CONFIG' : '/etc/py_dhcpd.conf',
	'TEMPLATE_CONFIG' : 'templates/dhcpd',
	'SCRIPT' : 'scripts/dhcpd',
	'EXIT_SCRIPT': 'scripts/dhcpd_exit',
	'ip_router' : '10.0.0.1',
	'ip_netmask' : '255.255.255.0',
	'ip_subnet' : '10.0.0.0',
	'ip_broadcast' : '10.0.0.255',
	'dns_1' : '8.8.8.8',
	'dns_2' : '8.8.4.4',
	'ip_range_min' : '10.0.0.3',
	'ip_range_max' : '10.0.0.12',
	'LOGFILE' : 'logs/dhcpd',
}

# NAT defaults
nat_defaults = {
		'SCRIPT' : 'scripts/nat',
		'LOGFILE'  : 'logs/nat',
}

default_parser = lambda x: dict([tup for tup in x.items()])
hostapd_default_parser = lambda x: dict([(tup[0], tup[1]['default']) for tup in x.items()])
# Default configuration dictionary
default_config = {
		'HOSTAPD': hostapd_default_parser(hostapd_defaults),
		'DHCP': default_parser(dhcp_defaults),
		'GENERAL': default_parser(general_defaults),
		'NAT': default_parser(nat_defaults),
		}


# Specific config options
# Following all Uppercase convention for special options. These are used by this python client for each section.
#
# SCRIPT -> Path of script which handles the start for a section, invoked when './hostapd.py start' is called.
# TEMPLATE_CONFIG -> path to the template file for a section which will be filled with values.
# OUTPUT_CONFIG -> File where the filled TEMPLATE_CONFIG will be stored.
# EXIT_SCRIPT -> Path of script which handles the exit for a section, invoked when './hostapd.py stop' is called.
# LOGFILE -> File where to store logs for a section
special_options = ['SCRIPT', 'TEMPLATE_CONFIG', 'OUTPUT_CONFIG', 'EXIT_SCRIPT', 'LOGFILE']

# Script Execution order
# Order in which each section is started
script_order = ['GENERAL', 'DHCP', 'NAT', 'HOSTAPD']
