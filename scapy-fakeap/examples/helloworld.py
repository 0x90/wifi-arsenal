# This example is a simple 'hello world' for scapy-fakeap.
# An open network will be created that can be joined by 802.11 enabled devices.

from fakeap import *

ap = FakeAccessPoint('mon0', 'github.com/rpp0/scapy-fakeap')
ap.run()