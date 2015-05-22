# Author: Tomasz bla Fortuna
# License: GPLv2

import main
LICENSE='GPLv2'

from log import Log
from watchdog import WatchDog

import sniffer
import analyzer
import web


# Placeholder for the global DB object injected into Flask request functions
db = None
