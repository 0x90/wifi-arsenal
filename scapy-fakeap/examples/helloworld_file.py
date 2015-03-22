# This example is a simple 'hello world' for scapy-fakeap.
# An open network will be created that can be joined by 802.11 enabled devices.
# The AP configuration is specified in 'example.conf'.

from fakeap import FakeAccessPoint

ap = FakeAccessPoint.from_file('example.conf')
ap.run()