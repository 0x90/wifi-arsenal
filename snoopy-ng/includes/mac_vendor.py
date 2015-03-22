#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import requests
import re
import logging
from urlparse import urlparse

#Set path
path = os.path.dirname(os.path.realpath(__file__))
manuf_url = "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD"

class mac_vendor():
    def __init__(self):
        self.mac_lookup = {}
        with open("%s/mac_vendor.txt" % path) as f:
            for line in f:
                line = line.strip()
                (mac, vendorshort, vendorlong) = line.split("|")
                self.mac_lookup[mac.lower()] = (vendorshort, vendorlong)

    def lookup(self, mac):
        mac = mac.lower()
        if mac in self.mac_lookup:
            return self.mac_lookup[mac]
        else:
            return ("Unknown", "Unknown device")

    def update(self, url=None):
        if not url:
            url = manuf_url
        o = urlparse(url)
        logging.debug("Fetching data from %s..." % url)
        if not o.scheme or o.scheme == "file":
            with open(url, "r") as f:
                data = f.read()
        elif o.scheme == "http" or o.scheme == "https":
            r = requests.get(url)
            data = r.text.encode("utf8")
        else:
            logging.error("Only local files or http(s) URLs are supported")
            return None

        count = 0
        f = open("%s/mac_vendor.txt" % path, "a")
        for line in data.split('\n'):
            try:
                mac, vendor = re.search(r'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})\t(.*)', line).groups()
                mac = mac.replace(":", "").lower()
                vendor = vendor.split("# ")
                vendorshort = vendor[0].strip()
                vendorlong = vendorshort
                if (len(vendor) == 2):
                    vendorlong = vendor[1].strip()
                if mac in self.mac_lookup:
                    continue
                f.write("|".join((mac.upper(), vendorshort, vendorlong + "\n")))
                self.mac_lookup[mac] = (vendorshort, vendorlong)
                count += 1
            except AttributeError:
                continue
            except:
                logging.error("Processing error - you may need to restore mac_vendor.txt manually.")
                return None

        f.close()
        logging.debug("Wrote %d new MAC vendor entries" % count)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(filename)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--update", help="Update OUI data from a text file in Wireshark manuf format", action='store_true')
    parser.add_argument("-f", "--file", help="The location of the Wireshark manuf file (useful if available locally)")
    args = parser.parse_args()

    if not args.update:
        print "[!] No operation specified! Try --help."
        sys.exit(-1)

    mv = mac_vendor()
    mv.update(args.file)



