# Copyright cozybit, Inc. - 2014
# All rights reserved

"""
An adapter used to map the wpa_supplicant tests cases for mesh onto real
hardware using wtf.
"""

import importlib
import os
import Queue as queue
import re
import subprocess
import sys
import threading
import time
import unittest
import wtf

WTFCONFIG = wtf.conf
STATIONS = WTFCONFIG.mps
ADAPTERS = None
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)

wpa_cli_error = ("Expected exit status of 0 from wpa_cli, got %d instead "
                 "(for command: '%s')")


def setUp(self):
    global ADAPTERS
    for station in STATIONS:
        station.comm.send_cmd("stop wpa_supplicant")
        station.comm.send_cmd("svc wifi disable")
    time.sleep(2)
    ADAPTERS = [WpasTestAdapter(sta) for sta in STATIONS]


def tearDown(self):
    for n in WTFCONFIG.nodes:
        n.stop()


class AdbCmdGen(object):
    @staticmethod
    def clear_logcat(adb_id):
        return ["adb", "-s", adb_id, "logcat", "-c"]

    @staticmethod
    def start_logcat(adb_id):
        return ["adb", "-s", adb_id, "logcat"]

    @staticmethod
    def wpa_cli(adb_id):
        return ["adb", "-s", adb_id, "shell", "wpa_cli",
                "-p/data/misc/wifi", "-iwlan0"]

    @staticmethod
    def dmesg(adb_id):
        return ["adb", "-s", adb_id, "shell", "cat", "/proc/kmsg"]


class WpaCliMonitor (object):

    EVENT_TRIM = re.compile(r'^[\s>]+')

    def __init__(self, q, adb_id, device_id):
        self._q = q
        self._adb_id = adb_id
        self._device_id = device_id

        self._wpacli_process = None
        self._logcat_process = None
        self._dmesg_process = None

        self._wpacli_logfp = None
        self._logcat_logfp = None
        self._dmesg_logfp = None

        self._wpacli_thread = None
        self._wpacli_stderr_thread = None
        self._logcat_out_thread = None
        self._logcat_err_thread = None
        self._dmesg_out_thread = None
        self._dmesg_err_thread = None

    def _gen(self):
        while True:
            line = self._wpacli_process.stdout.readline()
            if not line:
                return
            self._wpacli_logfp.write(line)
            line = line.strip()
            #print 'LaunchMonitorProcess:', repr(line)
            split = self.EVENT_TRIM.split(line)
            if len(split) > 1:
                line = split[1]
            if line.startswith("<3>"):
                yield line[3:]
            else:
                continue

    @staticmethod
    def _dump_fp_to_log(fp, logfp):
        while True:
            line = fp.readline()
            if not line:
                break
            logfp.write(line)

    def _wpa_cli_run(self, test_name):
        self._wpacli_process = subprocess.Popen(
            AdbCmdGen.wpa_cli(self._adb_id),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        subprocess.call(AdbCmdGen.clear_logcat(self._adb_id))

        self._logcat_process = (
            subprocess.Popen(AdbCmdGen.start_logcat(self._adb_id),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE))

        self._dmesg_process = (
            subprocess.Popen(AdbCmdGen.dmesg(self._adb_id),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE))

        self._wpacli_logfp = open("wpa_cli.%s.%s.log" %
                                  (test_name, self._device_id), "w")

        self._logcat_logfp = open("logcat.%s.%s.log" %
                                  (test_name, self._device_id), "w")

        self._dmesg_logfp = open("dmesg.%s.%s.log" %
                                 (test_name, self._device_id), "w")

        self._wpacli_stderr_thread = threading.Thread(
            target=self._dump_fp_to_log,
            args=(self._wpacli_process.stderr,
                  self._wpacli_logfp))

        self._wpacli_stderr_thread.start()

        self._logcat_out_thread = threading.Thread(
            target=self._dump_fp_to_log,
            args=(self._logcat_process.stdout,
                  self._logcat_logfp))

        self._logcat_out_thread.start()

        self._logcat_err_thread = threading.Thread(
            target=self._dump_fp_to_log,
            args=(self._logcat_process.stderr,
                  self._logcat_logfp))

        self._logcat_err_thread.start()

        self._dmesg_out_thread = threading.Thread(
            target=self._dump_fp_to_log,
            args=(self._dmesg_process.stdout,
                  self._dmesg_logfp))

        self._dmesg_out_thread.start()

        self._dmesg_err_thread = threading.Thread(
            target=self._dump_fp_to_log,
            args=(self._dmesg_process.stderr,
                  self._dmesg_logfp))

        self._dmesg_err_thread.start()

        for line in self._gen():
            self._q.put(line)

    def start(self, test_name):
        self._wpacli_thread = threading.Thread(target=self._wpa_cli_run,
                                               args=(test_name,))
        self._wpacli_thread.start()

    def stopMonitor(self):
        self._wpacli_process.kill()
        self._logcat_process.kill()
        self._dmesg_process.kill()
        self._wpacli_thread.join()
        self._wpacli_stderr_thread.join()
        self._logcat_out_thread.join()
        self._logcat_err_thread.join()
        self._dmesg_out_thread.join()
        self._dmesg_err_thread.join()
        self._wpacli_logfp.close()
        self._logcat_logfp.close()
        self._dmesg_logfp.close()


class EventMonitor (object):

    def __init__(self, sta):
        self._sta = sta
        self._q = queue.Queue()
        self._monitor = WpaCliMonitor(self._q,
                                      self._sta.comm.get_adb_id(),
                                      self._sta.comm.get_device_id())

    def waitForEvent(self, eventName):
        while True:
            line = self._q.get(timeout=10)
            #print 'waitForEvent:', line
            if line.startswith(eventName):
                return line

    def startMonitor(self, test_name):
        self._monitor.start(test_name=test_name)

    def stopMonitor(self):
        self._monitor.stopMonitor()


class WpasTestAdapter (object):

    def __init__(self, sta):
        self._sta = sta
        self._comm = sta.comm
        self._monitor = EventMonitor(sta)

    def startWpaCliMonitor(self, test_name):
        self._monitor.startMonitor(test_name)

    def stopWpaCliMonitor(self):
        self._monitor.stopMonitor()

    def getSTA(self):
        return self._sta

    def _send_to_wpa_cli(self, cmd):
        cmd = "wpa_cli -p/data/misc/wifi -iwlan0 " + cmd
        #print cmd
        code, resp = self._comm.send_cmd(cmd)
        if code != 0:
            raise ValueError(wpa_cli_error % (code, cmd))
        return str.join('', resp)

    def ping_wpa_supplicant(self):
        cmd = "wpa_cli -p/data/misc/wifi -iwlan0 ping"
        code, resp = self._comm.send_cmd(cmd)
        return code == 0 and str.join('', resp) == "PONG"

    def _send_cmd_bool_resp(self, cmd):
        resp = self._send_to_wpa_cli(cmd).strip()
        if resp != "OK":
            raise ValueError(resp)
        return resp

    def _send_cmd_int_resp(self, cmd):
        resp = self._send_to_wpa_cli(cmd).strip()
        if not resp.isdigit():
            raise ValueError(resp)
        return resp

    def dump_monitor(self):
        pass

    def request(self, req):
        return self._send_to_wpa_cli(req)

    def add_network(self):
        return self._send_cmd_int_resp("add_network")

    def set_network(self, networkId, prop, val):
        return self._send_cmd_bool_resp(
            "set_network " + networkId + " " + prop + " " + val)

    def set_network_quoted(self, networkId, prop, val):
        return self.set_network(networkId, prop, '\'"' + val + '"\'')

    def mesh_group_add(self, meshId):
        return self._send_cmd_bool_resp("mesh_group_add " + meshId)

    def mesh_group_remove(self):
        return self._send_cmd_bool_resp("mesh_group_remove wlan0")

    def remove_network(self, networkId):
        return self._send_cmd_bool_resp("remove_network " + networkId)

    def wait_event(self, eventList):
        for event in eventList:
            ev = self._monitor.waitForEvent(event)
            if ev is not None:
                return ev


def adb_ping_check(dev1, dev2):

    dev1.getSTA().comm.send_cmd("ip addr flush dev wlan0")
    dev1.getSTA().comm.send_cmd("ip addr add 10.0.0.2/24 dev wlan0")

    dev2.getSTA().comm.send_cmd("ip addr flush dev wlan0")
    dev2.getSTA().comm.send_cmd("ip addr add 10.0.0.3/24 dev wlan0")

    code, outp = dev1.getSTA().comm.send_cmd("ping -c5 10.0.0.3")
    if code != 0:
        raise Exception("No connectivity from dev1 to dev2")

    return


class WpasMeshTest(unittest.TestCase):

    def __init__(self, *args, **kw):
        unittest.TestCase.__init__(self, *args, **kw)
        fp = os.path.join(THIS_DIR, "..", "submodules", "wpa_supplicant",
                          "tests", "hwsim")
        sys.path.append(fp)
        module = importlib.import_module("test_wpas_mesh")
        self._tests = {}
        for name in module.__dict__.keys():
            if name.startswith("test_") or name.startswith("_test"):
                self._tests[name] = module.__dict__[name]

    def setUp(self):
        for adapter in ADAPTERS:
            adapter.getSTA().comm.send_cmd("start wpa_supplicant")
            while not adapter.ping_wpa_supplicant():
                time.sleep(0.5)
            adapter.startWpaCliMonitor(self.id())

    def tearDown(self):
        for adapter in ADAPTERS:
            adapter.stopWpaCliMonitor()
            adapter.getSTA().comm.send_cmd("stop wpa_supplicant")

    def test_wpas_add_set_remove_support(self):
        self._tests['test_wpas_add_set_remove_support'](ADAPTERS)

    def test_wpas_mesh_group_added(self):
        self._tests['test_wpas_mesh_group_added'](ADAPTERS)

    def test_wpas_mesh_group_remove(self):
        self._tests['test_wpas_mesh_group_remove'](ADAPTERS)

    def test_wpas_mesh_peer_connected(self):
        self._tests['test_wpas_mesh_peer_connected'](ADAPTERS)

    def test_wpas_mesh_peer_disconnected(self):
        self._tests['test_wpas_mesh_peer_disconnected'](ADAPTERS)

    def test_wpas_mesh_mode_scan(self):
        self._tests['test_wpas_mesh_mode_scan'](ADAPTERS)

    def test_wpas_mesh_open(self):
        self._tests['_test_wpas_mesh_open'](ADAPTERS, None, adb_ping_check)

    def test_wpas_mesh_open_no_auto(self):
        self._tests['_test_wpas_mesh_open_no_auto'](ADAPTERS, None,
                                                    adb_ping_check)

    def test_wpas_mesh_secure(self):
        self._tests['_test_wpas_mesh_secure'](ADAPTERS, None, adb_ping_check)

    def test_wpas_mesh_secure_no_auto(self):
        self._tests['_test_wpas_mesh_secure_no_auto'](ADAPTERS, None,
                                                      adb_ping_check)
