import wtf.node.mesh
import wtf.comm
import wtf

from wtf.node import PlatformOps


subnet = "192.168.2"
meshid = "meshmesh"
channel = 1
htmode = "HT20"
zotacs = []
driver = "ath9k"


# pre-configured zotac nodes
for n in range(4):
# comms
    z_ssh = wtf.comm.SSH(ipaddr="192.168.3.15" + str(n + 1))
    ops = PlatformOps(z_ssh)
    z_ssh.name = "zotac-" + str(n)
    z_ssh.verbosity = 2

    ifaces = []
    configs = []

# iface + ip
    iface = wtf.node.Iface.create_iface(name="wlan0", driver=driver,
                                        ip="%s.%d" % (subnet, 10 + n),
                                        ops=ops)
    ifaces.append(iface)
# BSS
    configs.append(wtf.node.mesh.MeshConf(
        ssid=meshid, channel=channel, htmode=htmode, iface=ifaces[0]))
    ifaces[-1].conf = configs[-1]

    z = wtf.node.mesh.MeshSTA(z_ssh, ifaces=ifaces, ops=ops)
    z.configs = configs

    zotacs.append(z)

# XXX: decouple testbed description from the specific test suite
wtf.conf = wtf.config("simplemesh", nodes=zotacs,
                      name="simple two zotac mesh throughput test")
