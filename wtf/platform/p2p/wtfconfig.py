import wtf.node.p2p
import wtf.comm
import wtf

p1_comm = wtf.comm.SSH(ipaddr="192.168.1.80")
p1_comm.name = "NODE 1"
p1_comm.verbosity = 2
p1 = wtf.node.p2p.Wpap2p(p1_comm, "wlan0", path="/root")

p2_comm = wtf.comm.SSH(ipaddr="192.168.1.90")
p2_comm.name = "NODE 2"
p2_comm.verbosity = 2
p2 = wtf.node.p2p.Wpap2p(p2_comm, "wlan0", path="/root")

# Marvell's mvdroid p2p node, which uses wfdd, wfd_cli, and wpa_supplicant is
# also supported.  Create such a node like this:
#p2_comm = wtf.comm.MvdroidSerial(port="/dev/ttyUSB0")
#p2_comm.name = "mvdroid"
#p2_comm.verbosity = 2

# NOTE: the force_driver_reload option to the Mvdroid constructor forces a full
# reload of the underlying driver at node start/stop time instead of node
# init/shutdown time.  Currently, this option must be set to true to prevent
# the state of one test influencing another test.  Clearly, in a real system
# you would not want to reload the drivers for each wifi-direct use case.  So
# this is a bug in mvdroid.  Once it's fixed, we can stop using
# force_driver_reload=True.
#p2 = wtf.node.p2p.Mvdroid(p2_comm, force_driver_reload=True)

wtf.conf = wtf.config("p2p", nodes=[p1, p2], name="wpa supplicant p2p")
