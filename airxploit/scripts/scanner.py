#!/usr/bin/python
"""
 Example for the airxploit scripting interface
 Load all scanner and discovery plugins and scan in an endless loop
"""

from time import sleep
import sys
sys.path.append("../src")
import airxploit

pcc = airxploit.core.plugin_control_center.Plugin_Control_Center()
airctl = airxploit.core.aircontroller.AirController(pcc)
airview = airxploit.view.console.ConsoleView(pcc)
airview.header()

for plugin in airctl.getScannerPlugins():
    airctl.loadScannerPlugin(plugin)

for plugin in airctl.getDiscoveryPlugins():
    airctl.loadDiscoveryPlugin(plugin)

while True:
    airctl.scan()
    sleep(10)
	