import wtf.node.p2p
import wtf.comm
import wtf

p1_comm = wtf.comm.MvdroidSerial(port="/dev/ttyUSB0")
p1_comm.name = "mvdroid-1"
p1_comm.verbosity = 2
p1 = wtf.node.p2p.Mvdroid(p1_comm)

p2_comm = wtf.comm.MvdroidSerial(port="/dev/ttyUSB1")
p2_comm.name = "mvdroid-2"
p2_comm.verbosity = 2
p2 = wtf.node.p2p.Mvdroid(p2_comm)

wtf.conf = wtf.config("mvdroid", nodes=[p1, p2], name="mvdroid p2p tests")
