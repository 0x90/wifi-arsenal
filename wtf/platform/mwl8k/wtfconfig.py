import wtf.node.ap
import wtf.node.sta
import wtf.comm
import wtf

# I've got an mwl8k dev board on serial port ttyUSB4
mwl8k_comm = wtf.comm.Serial(
    port="/dev/ttyUSB4", prompt="[root@fedora-arm /]# ")
mwl8k_comm.name = "mwl8k"
mwl8k_comm.verbosity = 2
mwl8k_ap = wtf.node.ap.Hostapd(mwl8k_comm, "wlan0")

# create a configuration for a nearby STA
sta_ssh = wtf.comm.SSH(ipaddr="192.168.1.80")
sta_ssh.name = "STA"
sta_ssh.verbosity = 2
sta = wtf.node.sta.LinuxSTA(sta_ssh, "wlan0")

wtf.conf = wtf.config("ap_sta", nodes=[mwl8k_ap, sta], name="mwl8k as AP")
