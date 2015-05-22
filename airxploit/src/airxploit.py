#!/usr/bin/python2

from airxploit.view.console import ConsoleView
from airxploit.core.plugin_control_center import PluginControlCenter
import logging
import sys

logging.basicConfig(filename='airxploit.log', level=logging.DEBUG)

airview = ConsoleView( PluginControlCenter() )

airview.header()

try:
    airview.run()
except KeyboardInterrupt:
    sys.exit(1)
