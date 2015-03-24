import wtf.node.mesh
import wtf.comm

subnet = "192.168.34"
meshid = "meshmesh"
channel = 1
htmode = "HT20"
zotacs = []

# pre-configured zotac nodes
for n in range(10, 13):
# comms
    z_ssh = wtf.comm.SSH(ipaddr="10.10.10." + str(n))
    z_ssh.name = "zotac-" + str(n)
    z_ssh.verbosity = 2

    if n == 12 or n == 11:
        channel = 149

    ifaces = []

# iface + ip
    ifaces.append(wtf.node.Iface(name="wlan0", driver="ath9k", ip="%s.%d" %
                  (subnet, 10 + n)))
# BSS
    ifaces[-1].conf = wtf.node.mesh.MeshConf(ssid=meshid, channel=channel,
                                             htmode=htmode, iface=ifaces[-1], shared=False)

# "middle" node
    if n == 11:
        ifaces.append(
            wtf.node.Iface(name="wlan1", driver="ath9k", ip="%s.%d" % (subnet, 40 + n)))
        ifaces[-1].conf = wtf.node.mesh.MeshConf(ssid=meshid,
                                                 channel=1, htmode=htmode, iface=ifaces[-1], shared=False)
        ifaces.append(wtf.node.Iface(name="eth1"))
        # XXX: hack! mesh nodes don't expect non-mesh configs
        ifaces[-1].enable = False

    z = wtf.node.mesh.MeshSTA(z_ssh, ifaces=ifaces)

    zotacs.append(z)

# extra guy to act as outside PC
z_ssh = wtf.comm.SSH(ipaddr="10.10.10.13")
z_ssh.name = "zotac-13"
z_ssh.verbosity = 2
ifaces = []
ifaces.append(wtf.node.Iface(name="eth1"))
ifaces[-1].enable = False
z = wtf.node.mesh.MeshSTA(z_ssh, ifaces=ifaces)
zotacs.append(z)

# configure your sniffer node here
# ifaces=[]
#ssh = wtf.comm.SSH(ipaddr="supersniffer.local")
#ssh.name = "sniffer"
#ssh.verbosity = 2
#ifaces.append(wtf.node.Iface(name="intel", driver="iwl4965"))
#ifaces[-1].conf = wtf.node.sniffer.SnifferConf(channel=1, htmode=htmode, iface=ifaces[-1])
#ifaces.append(wtf.node.Iface(name="ath9k", driver="ath9k"))
##ifaces[-1].conf = wtf.node.sniffer.SnifferConf(channel=1, htmode=htmode, iface=ifaces[-1])
#sniffer = wtf.node.sniffer.SnifferSTA(ssh, ifaces=ifaces)
# zotacs.append(sniffer)

# XXX: decouple testbed description from the specific test suite
wtf.conf = wtf.config("mmultichan", nodes=zotacs, name="mesh multichan")
