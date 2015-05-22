import wtf.node.mesh
import wtf.node.sniffer
import wtf.comm
import wtf

subnet = "192.168.34"
zotacs = []

# pre-configured zotac nodes
for n in range(10, 12):
# comms
    z_ssh = wtf.comm.SSH(ipaddr="10.10.10." + str(n))
    z_ssh.name = "zotac-" + str(n)
    z_ssh.verbosity = 2

    ifaces = []
    configs = []

# iface + ip
    ifaces.append(wtf.node.Iface(name="wlan0", driver="ath9k", ip="%s.%d" %
                  (subnet, str(10 + n))))
# BSS
    configs.append(wtf.node.mesh.MeshConf(ssid="meshpoo",
                   channel=channel, htmode="HT20", iface=ifaces[0]))

    z = wtf.node.mesh.MeshSTA(z_ssh, ifaces=ifaces)
    z.configs = configs

    zotacs.append(z)

# XXX: decouple testbed description from the specific test suite
wtf.conf = wtf.config("11aa", nodes=zotacs, name="11aa mesh")
