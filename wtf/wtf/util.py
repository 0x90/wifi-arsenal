"""Collection of misc utils for WTF."""
import sys
import commands
import os
import subprocess
import random


CAP_FILE = "/tmp/out.cap"


class LinkReport():

    """A collection of different link metric results."""

    def __init__(self, perf_report=None, vqm_report=None):
        self.perf = perf_report
        self.vqm = vqm_report


class VQMReport():

    """VQMReport."""

    def __init__(self, ref_clip="", out_clip="", ssim=0, psnr=0, dcm=0):
        self.ref_clip = ref_clip
        self.out_clip = out_clip
        self.ssim = ssim
        self.psnr = psnr
        self.dcm = dcm


class CapData():

    """CapData."""

    def __init__(self, cap_file=None, monif=None, promisc=False):
        # local to the monif
        self.node_cap = cap_file
        self.local_cap = None
        self.monif = monif
        self.promisc = promisc
        self.pid = None
        self.snaplen = None


class PerfConf():

    """PerfConf."""

    def __init__(self, server=False, dst_ip=None, timeout=5,
                 dual=False, b=10, p=7777, L=6666, fork=False,
                 tcp=False):
        self.server = server
        self.dst_ip = dst_ip
        self.timeout = timeout
        self.dual = dual
        self.bw = b
        self.tcp = tcp
        self.listen_port = p
        self.dual_port = L
        self.fork = fork
        self.report = None
        self.pid = None


class IperfReport():

    """IperfReport."""

    def __init__(self, throughput=0.0, loss=0.0):
        self.tput = throughput
        self.loss = loss


def reconf_stas(stas):
    for sta in stas:
        sta.reconf()


def tu_to_s(tu):
    return tu * 1024 / 1000 / float(1000)


def tu_to_us(tu):
    return tu * 32 * 32


def start_captures(stas):
    for sta in stas:
        for iface in sta.iface:
            sta.start_capture(iface)


def stop_captures(stas, cap_file=CAP_FILE):
    i = 0
    for sta in stas:
        if cap_file == CAP_FILE:
            cap_file += str(i)
        for iface in sta.iface:
            sta.stop_capture(iface, cap_file)
        i += 1


def killperfs(stas):
    for sta in stas:
        for iface in sta.iface:
            iface.killperf()


def get_vqm_report(ref_clip, out_clip):
    print "getting VQM for " + out_clip

    # XXX: the qpsnr metrics are currently more or less bogus since it will
    # blindly compare the reference and output clips frame-by-frame, but both
    # clips won't start at the *same* frame (due to client-side buffering).
    # Although there is a correlation where SSIM closer to 1 means better
    # quality, see DCM for a more reliable quality metric.

    # comment these out for now since they take a lot of time.
    # TODO: follow their stdout

    #    o = commands.getoutput("qpsnr -a avg_ssim -s100 -m1000 -o fpa=1000 -r
    #    %s %s" % \ (ref_clip, out_clip))
    #    print o

    # final result should be on the last line
    #    avg_ssim = o.splitlines()[-1].split(",")[1]
    #

    #    o = commands.getoutput("qpsnr -a avg_psnr -s100 -m1000 -o fpa=1000 -r
    #    %s %s" % \ (ref_clip, out_clip))
    #    print o
    # final result should be on the last line
    #    avg_psnr = o.splitlines()[-1].split(",")[1]
    #
    # DCM == Dumb Completion Metric :D

    dcm = float(os.path.getsize(out_clip)) / os.path.getsize(ref_clip)
    avg_ssim = 0
    avg_psnr = 0
    return VQMReport(ref_clip, out_clip, avg_ssim, avg_psnr, dcm)


def do_vqm(ifaces, dst, ref_clip):
    # XXX: a bit nasty, test better be 1 frames above us!
    rcv_clip = "/tmp/" + sys._getframe(1).f_code.co_name + ".ts"
    rtp_port = 5004

    # destination needs to match client in unicast.
    client = None
    for iface in ifaces:
        if dst == iface.ip:
            client = iface
            continue
        server = iface

    # at least make transmitter (sta0) consistent in mcast case.
    if client == None:
        server = ifaces[0]
        client = ifaces[1]

    client.video_client(ip=dst, port=rtp_port)
    server.video_serve(video=ref_clip, ip=dst, port=rtp_port)

    client.get_video(rcv_clip)
    return get_vqm_report(ref_clip, rcv_clip)


def parse_perf_report(conf, r):
    """CSV iperf report as @r."""
    if len(r) == 0:
        tput = 0
        loss = 0
    elif conf.tcp == True:
        tput = float(r[0].split(',')[-1]) / (1024 * 1024)  # bits -> mbits
        loss = 0.0  # no loss stats with TCP...
    else:
    # output comes as list of strings, hence r[0]...
        tput = float(r[0].split(',')[-6]) / (1024 * 1024)  # bits -> mbits
        loss = float(r[0].split(',')[-2])
    return IperfReport(tput, loss)


def do_perf(ifaces, dst, tcp=False, bwidth=100):
    # perform performance report between interfaces listed in ifaces[] and
    # return report as an IperfReport destination needs to match server in
    # unicast.

    server = None
    for iface in ifaces:
        if dst == iface.ip:
            server = iface
            continue
        client = iface

    # at least make transmitter consistent in mcast case.
    if server == None:
        server = ifaces[1]
        client = ifaces[0]

    server.perf_serve(dst_ip=dst, tcp=tcp)
    client.perf_client(dst_ip=dst, timeout=10, b=bwidth, tcp=tcp)
    server.killperf()
    return server.get_perf_report()


def do_tshark(cap_file, tshark_filter, extra=""):
    # return packets found in tshark_filter
    r, o = commands.getstatusoutput("tshark -r" + cap_file + " -R'" + tshark_filter +
                                    "' " + extra + " 2> /dev/null")
    if r != 0 and r != 256:
        raise Exception(
            "tshark error %d! Is tshark installed and %s exists? Please verify filter %s" %
            (r, cap_file, tshark_filter))
    return o


def print_linkreports(results):
    header = "TEST             "
    # assuming we have same stats for all the tests...
    if results.values()[0].perf != None:
        header += "THROUGHPUT(Mb/s)        LOSS(%)       "
    if results.values()[0].vqm != None:
        header += "SSIM        PSNR      DCM     FILE           "
    print header
    for test in sorted(results):
        result = results[test]
        line = "%s      " % (test,)
        if result.perf != None:
            perf = result.perf
            line += "%f         %f      " % (perf.tput, perf.loss)
        if result.vqm != None:
            vqm = result.vqm
            line += "%s     %s  %s  %s      " % (vqm.ssim,
                                                 vqm.psnr, vqm.dcm, vqm.out_clip)
        print line


def gen_mesh_id():
    return "wtfmesh" + str(random.randint(1, 1000))


def get_adb_id(device_id):
    cmd = ["adbs", "-s", device_id, "-i"]
    sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    adb_id, err = sp.communicate()
    if sp.returncode != 0:
        print sp.returncode, adb_id, err
        return None
    adb_id = adb_id.strip()
    return adb_id


def is_dev_connected(device_id):
    adb_id = get_adb_id(device_id)
    if adb_id is None:
        return False
    ls = subprocess.check_output(["adb", "devices"]).strip().splitlines()
    ls = [L.split()[0] for L in ls[1:]]
    return adb_id in ls


def logMeasurement(name, value):
    '''
    log a measurement result to stdout

    @param name: a string name for measurement variable
    @param value: a string representation of numeric value

    '''
    print '<measurement><name>%s</name>;' % (name) + \
        '<value>%s</value></measurement>;' % (value)


def get_topology(ifaces, filename="topology"):
    """Make .svg file with topology."""
    _filename = filename + ".dot"
    neighbors = {}
    alias = {}
    # make alias for graph instead of using mac address
    i = 1
    for iface in ifaces:
        alias[iface.mac] = "STA" + str(i)
        i += 1

    # dump mpaths and keep next hop
    for iface in ifaces:
        _, o = iface.node.comm.send_cmd("iw " + iface.name + " mpath dump")
        out = []
        for line in o:
            if iface.name in line:
                out.append(line.split()[1])
        iface_mac = iface.mac
        neighbors[iface_mac] = []
        for next_hop in out:
            if next_hop not in neighbors[iface.mac]:
                neighbors[iface_mac].append(next_hop)

    f = open(_filename, 'w')
    f.write("digraph %s {\n" % (filename))
    for key, macs in neighbors.iteritems():
        for mac in macs:
            f.write("%s " % (alias[key]))
            f.write("-> %s;\n" % (alias[mac]))
    f.write("}")
    f.close()
