#!/usr/bin/env python

import errno
import sys
import types
from mac2defaults import default_key, default_ssid
try:
    import pythonwifi.flags
    from pythonwifi.iwlibs import Wireless, Iwrange, getNICnames
except ImportError:
    sys.stderr.write("Error: missing pythonwifi module\n")
    sys.exit(1)

def print_probable_keys(wifi):
    """ Print the probable keys
    """
    # "Check if the interface could support scanning"
    try:
        iwrange = Iwrange(wifi.ifname)
    except IOError, (error_number, error_string):
        sys.stderr.write("%-8.16s  Interface doesn't support scanning.\n\n" % (
                            wifi.ifname))
    else:
        try:
            results = wifi.scan()
        except IOError, (error_number, error_string):
            if error_number == errno.EPERM:
                sys.stderr.write("Permission denied. Did you run the program as root?\n")
            else:
                sys.stderr.write(
                    "%-8.16s  Interface doesn't support scanning : %s\n\n" %
                    (wifi.ifname, error_string))
        else:
            for ap in results:
                if "Master" == ap.mode:
                    defaultkey = default_key(ap.bssid)
                    defaultessid = default_ssid(ap.bssid)
                    if ap.essid[-4:] == defaultessid:
                        print "* %s: %s" % (ap.essid, defaultkey)
                    else:
                        print "- %s: %s" % (ap.essid, defaultkey)


def main():
    # if only program name is given, print usage info
    if len(sys.argv) == 1:
        ifname = "wlan0"
    else:
        ifname = sys.argv[1]
    wifi = Wireless(ifname)
    print_probable_keys(wifi)

if __name__ == "__main__":
    main()
