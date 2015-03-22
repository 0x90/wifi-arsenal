#!usr/bin/python

# == Configuration file for AirMode ==
#
# This script is used for configure your installation of AirMode
# Follow the comments for a correct configuration, and please don't modify
# undocumented lines.
#
# Using correctly this file, it's possible to automate repetitive tasks, and
# make the program much more powerful.
#
# After all, "everyone can use a tool, but professional is recognized by his
# configuration file".
#




# Don't modify these lines
#
import sys
import os
import time
import re
import commands
#import subprocess



#
# Program directories
#

#
# Home directory:
# home_dir   = os.getenv('HOME')
#
home_dir = os.getenv('HOME')

#
# Config directory:
# config_dir = home_dir + '/.airmode/'
#
config_dir = str(home_dir )+ '/.airmode/'



#
# Default color terminal:
# def_term = 'xterm'
#
def_term = 'mate-terminal'



#
# Key database
#
# Database path:
# database_path = config_dir + 'key-database.db';
database_path = config_dir + 'key-database.db';



#
# Other variables used by the program
#
selected_interface = ''



#
# Init and end function, called by the program.
#
# Very useful for automating tasks or commands (such as 'macchanger',
# 'ifconfig up', 'airmon-ng')
#

#
# Init function (called when the program starts)
#
def config_init():

    #
    # Example: Automatically prepare an interface
    #
    # 1) check if interface is present
    # 2) change the mac address to a random one
    # 3) enable monitor mode
    # 4) select the interface
    #
    # intf = 'wlan0'
    # if wifi_interface_is_present(intf):
    #     set_random_mac(intf)
    #     set_wifi_mode(intf, 'monitor')
    #     select_interface = intf
        

    return 0

#
# End function (called when the program ends)
#
def config_end():

    #
    # Example: disable an interface
    #
    # intf = 'wlan0'
    # if wifi_interface_is_present(intf):
    #     exec_command("ifconfig " + intf + " down")
    #

    return 0







#
# == CONFIGURATION ENDS HERE ==
#







#
#  UTILITIES
# (Than you don't need to modify) ;)
#

#
# Execute a command
#
def exec_command(cmd):
    return subprocess.getstatusoutput(cmd)[0]

#
# Check if a wireless interface is present
#
def wifi_interface_is_present(interface):

    if exec_command('iwconfig 2>&1 | grep 802.11 | grep' + interface):
        return True

    return False

#
# Set random MAC address
#
def set_random_mac(interface):

    if exec_command('ifconfig ' + interface + ' down') != 0:
        return
    if exec_command('macchanger --random ' + interface) != 0:
        return
    if exec_command('ifconfig ' + interface + ' up') !=0:
        return

#
# Set wireless interface mode
#
def set_wifi_mode(interface, mode):
    if exec_command('ifconfig ' + interface + ' down') != 0:
        return
    if exec_command('iwconfig ' + interface + ' mode ' + mode) != 0:
        return
    if exec_command('ifconfig ' + interface + ' up') != 0:
        return

