import subprocess
import re
import os
import platform

VERBOSITY = 1
RUNNING_ON_PI = platform.machine() == 'armv6l'

class Level:
    CRITICAL = 0
    INFO = 1
    DEBUG = 2

class Color:
    GREY    = '\x1b[1;37m'
    GREEN   = '\x1b[1;32m'
    BLUE    = '\x1b[1;34m'
    YELLOW  = '\x1b[1;33m'
    RED     = '\x1b[1;31m'
    MAGENTA = '\x1b[1;35m'
    CYAN    = '\x1b[1;36m'

def clr(color, text):
    return color + str(text) + '\x1b[0m'

def check_root():
    dev_null = open(os.devnull, 'w')

    try:
        subprocess.check_output(['cat', '/etc/shadow'], stderr = dev_null)
    except subprocess.CalledProcessError:
        debug_print(clr(Color.RED, "Run as root."), Level.CRITICAL)
        exit(1)

def set_monitor_mode(wlan_dev, enable=True):
    monitor_dev = None
    if enable:
        result = subprocess.check_output(['airmon-ng', 'start', wlan_dev])
        if not "monitor mode enabled on" in result:
            debug_print(clr(Color.RED, "ERROR: Airmon could not enable monitor mode on device %s. Make sure you are root, and that" \
                "your wlan card supports monitor mode." % wlan_dev), Level.CRITICAL)
            exit(1)
        monitor_dev = re.search(r"monitor mode enabled on (\w+)", result).group(1)

        debug_print("Airmon set %s to monitor mode on %s" % (wlan_dev, monitor_dev), Level.INFO)
    else:
        subprocess.check_output(['airmon-ng', 'stop', wlan_dev])

    return monitor_dev

def debug_print(string, level):
    if VERBOSITY >= level:
        print(string)

def bytes_to_hex(string):
    result = ""
    for letter in string:
        result += (hex(ord(letter))).split('0x')[1] + ':'
    result = result.rstrip(':')

    return result