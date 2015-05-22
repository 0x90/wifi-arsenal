import wtf.node.mesh
import wtf.node.sniffer
import wtf.comm
import wtf

subnet = "192.168.34"
channel = 108
meshid = "meshmesh"
zotacs = []
ifaces = []
configs = []

# pre-configured zotac nodes
for n in range(8, 12):
# comms
    z_ssh = wtf.comm.SSH(ipaddr="10.10.10." + str(n))
    z_ssh.name = "zotac-" + str(n)
    z_ssh.verbosity = 2

# iface + ip
    ifaces.append(wtf.node.Iface(name="wlan0", driver="ath9k", ip="%s.%d" %
                  (subnet, str(10 + n))))
# BSS
    configs.append(wtf.node.mesh.MeshConf(
        ssid=meshid, channel=channel, htmode="HT20", iface=ifaces[0]))

    z = wtf.node.mesh.MeshSTA(z_ssh, ifaces=ifaces)
    z.configs = configs

    zotacs.append(z)

# configure your sniffer node here
ssh = wtf.comm.SSH(ipaddr="10.10.10." + str(6))
ssh.name = "sniffer"
ssh.verbosity = 2
ifaces = []
configs = []
ifaces.append(wtf.node.Iface(name="wlan0", driver="ath9k"))
configs.append(wtf.node.mesh.MeshConf(
    channel=channel, htmode="HT20", iface=ifaces[0]))
sniffer = wtf.node.sniffer.SnifferSTA(
    ssh, iface="wlan0", driver="ath9k", ifaces=ifaces)
sniffer.configs = configs
zotacs.append(sniffer)

# XXX: decouple testbed description from the specific test suite
wtf.conf = wtf.config("mcca", nodes=zotacs, name="zotac mesh")
