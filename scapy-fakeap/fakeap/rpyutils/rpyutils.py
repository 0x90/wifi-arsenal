import subprocess
import re
import os
import struct
from scapy.arch import str2mac, get_if_raw_hwaddr


class Level:
    CRITICAL = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3
    BLOAT = 4

VERBOSITY = Level.INFO


class Color:
    GREY = '\x1b[1;37m'
    GREEN = '\x1b[1;32m'
    BLUE = '\x1b[1;34m'
    YELLOW = '\x1b[1;33m'
    RED = '\x1b[1;31m'
    MAGENTA = '\x1b[1;35m'
    CYAN = '\x1b[1;36m'


def clr(color, text):
    return color + str(text) + '\x1b[0m'


def check_root():
    if not os.geteuid() == 0:
        printd(clr(Color.RED, "Run as root."), Level.CRITICAL)
        exit(1)


def check_root_shadow():
    dev_null = open(os.devnull, 'w')

    try:
        subprocess.check_output(['cat', '/etc/shadow'], stderr=dev_null)
    except subprocess.CalledProcessError:
        printd(clr(Color.RED, "Run as root."), Level.CRITICAL)
        exit(1)


def set_monitor_mode(wlan_dev, enable=True):
    monitor_dev = None
    if enable:
        result = subprocess.check_output(['airmon-ng', 'start', wlan_dev])
        if not "monitor mode enabled on" in result:
            printd(clr(Color.RED, "ERROR: Airmon could not enable monitor mode on device %s. Make sure you are root, and that" \
                                       "your wlan card supports monitor mode." % wlan_dev), Level.CRITICAL)
            exit(1)
        monitor_dev = re.search(r"monitor mode enabled on (\w+)", result).group(1)

        printd("Airmon set %s to monitor mode on %s" % (wlan_dev, monitor_dev), Level.INFO)
    else:
        subprocess.check_output(['airmon-ng', 'stop', wlan_dev])

    return monitor_dev


def set_ip_address(dev, ip):
    if subprocess.call(['ip', 'addr', 'add', ip, 'dev', dev]):
        printd("Failed to assign IP address %s to %s." % (ip, dev), Level.CRITICAL)

    if subprocess.call(['ip', 'link', 'set', 'dev', dev, 'up']):
        printd("Failed to bring device %s up." % dev, Level.CRITICAL)


def clear_ip_tables():
    if subprocess.call(['iptables', '--flush']):
        printd("Failed to flush iptables.", Level.CRITICAL)
    if subprocess.call(['iptables', '--table', 'nat', '--flush']):
        printd("Failed to flush iptables NAT.", Level.CRITICAL)
    if subprocess.call(['iptables', '--delete-chain']):
        printd("Failed to delete iptables chain.", Level.CRITICAL)
    if subprocess.call(['iptables', '--table', 'nat', '--delete-chain']):
        printd("Failed to delete iptables NAT chain.", Level.CRITICAL)


def printd(string, level):
    if VERBOSITY >= level:
        print(string)


def hex_offset_to_string(byte_array):
    temp = byte_array.replace("\n", "")
    temp = temp.replace(" ", "")
    return temp.decode("hex")


def get_frequency(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)

    freq_string = struct.pack("<h", freq)

    return freq_string


def mac_to_bytes(mac):
    return ''.join(chr(int(x, 16)) for x in mac.split(':'))


def bytes_to_mac(byte_array):
    return ':'.join("{:02x}".format(ord(byte)) for byte in byte_array)


# Scapy sees mon0 interface as invalid address family, so we write our own
def if_hwaddr(iff):
    return str2mac(get_if_raw_hwaddr(iff)[1])


def set_debug_level(lvl):
    global VERBOSITY
    VERBOSITY = lvl