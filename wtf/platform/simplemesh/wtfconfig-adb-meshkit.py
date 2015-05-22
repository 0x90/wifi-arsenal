"""Basic tests for a mesh network on Android using MeshKit."""

import wtf.node.mesh
import wtf.comm

from wtf.util import gen_mesh_id, is_dev_connected
from wtf.node import AndroidPlatformOps

subnet = "192.168.4"

meshid = gen_mesh_id()

channel = 36
htmode = "HT20"
phones = []
n = 0

# add your driver here
MARVEL_DRIVER = "mwl8787_sdio"
QCA_DRIVER = "wcn36xx_msm"

potential_devices = [
    "JGT1", "JGT2", "JGT3",
    "GT9", "GT10", "GT11",
    "SXZ1", "SXZ2", "SXZ3",
    "XZ1", "XZ2", "XZ3", "XZ4",
]

devices = []
exp_results = {"test1": 30.0, "test2": 15.0}

# add as DUT's connecte devices only
for device in potential_devices:
    if is_dev_connected(device):
        devices.append(device)

for dev in devices:
    n += 1
    android_adb = wtf.comm.ADB(dev)
    ops = AndroidPlatformOps(android_adb)
    android_adb.name = dev
    android_adb.verbosity = 2

    ifaces = []
    configs = []

    if dev.startswith("XZ") or dev.startswith("SXZ"):
        driver = QCA_DRIVER
    elif dev.startswith("JGT") or dev.startswith("GT"):
        driver = MARVEL_DRIVER
    else:
        raise ValueError("Don't know which driver to use")

    iface = wtf.node.Iface.create_iface(name="mesh0", driver=driver,
                                        ip="%s.%d" % (subnet, 10 + n),
                                        ops=ops)

    ifaces.append(iface)
    configs.append(wtf.node.mesh.MeshConf(ssid=meshid, channel=channel,
                                          htmode=htmode, iface=ifaces[0]))
    ifaces[-1].conf = configs[-1]

    adb = wtf.node.mesh.MeshKitSTA(android_adb, ifaces=ifaces, ops=ops)
    adb.configs = configs

    phones.append(adb)

if len(devices) >= 2:
    wtf.conf = wtf.config("simplemesh", nodes=phones,
                          name="mesh tests over adb",
                          exp_results=exp_results)
else:
    raise ValueError("Number of devices connected was too small!")
