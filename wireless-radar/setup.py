#/usr/bin/env python2
import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "wireless-radar",
    version = "0.2",
    author = "Stefan Marsiske",
    author_email = "s@ctrlc.hu",
    description = ("various tools to map the wireless environment"),
    license = "AGPLv3",
    keywords = "802.11 wireless wifi scanning direction-finding",
    url = "https://github.com/stef/wireless-radar",
    packages = ['wirelessradar'],
    entry_points = {
       'console_scripts': [
           'wprox = wirelessradar.wprox:main',
           'bprox = wirelessradar.bprox:main',
           'wscan = wirelessradar.wscan:main',
           'mrssi = wirelessradar.mrssi:main',
           'rfdiff = wirelessradar.rfdiff:main',
          ],
       },
    long_description=read('README.md'),
    install_requires = ("scapy", "netaddr", "python_wifi==0.5.0", "pybluez"),
    dependency_links=[ "git+https://github.com/pingflood/pythonwifi.git#egg=python_wifi-0.5.0", ],
    classifiers = ["Development Status :: 4 - Beta",
                   "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
                   ],
)
