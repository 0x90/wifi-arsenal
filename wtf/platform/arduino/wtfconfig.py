import wtf
import wtf.node.ap
import wtf.comm
import wtf.node.sta
from wtf.node import PlatformOps

# path to arduino directory... must be changed
IDE = "/home/jacob/dev/arduino_project/MeshableMCU/arduino-1.5.6-r2"

arduino_comm = wtf.comm.Serial(port="/dev/ttyUSB2", prompt="")
arduino_comm.name = "arduino"
arduino_comm.verbosity = 2

# make zotac-0 hostapd to check that wifi tests are working
sta_ssh = wtf.comm.SSH(ipaddr="zotac-3.local")
sta_ssh.name = "zotac-3"
sta_ssh.verbosity = 2
ops = PlatformOps(sta_ssh)
iface = wtf.node.Iface.create_iface(name="wlan0", driver="ath9k", ops=ops)
sta = wtf.node.ap.Hostapd(sta_ssh, [iface], ops=ops)

wtf.conf = wtf.config("arduino", comm=arduino_comm, nodes=[sta],
                      name="arduino mc200 tests", data={'IDE': IDE})
