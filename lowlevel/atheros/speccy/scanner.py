#!/usr/bin/python
from multiprocessing import Process
import os
import time

class Scanner(object):

    interface = None
    freqlist = None
    process = None
    debugfs_dir = None

    def _find_debugfs_dir(self):
        ''' search debugfs for spectral_scan_ctl for this interface '''
        netdev_dir = 'netdev:%s' % self.interface
        for dirname, subd, files in os.walk('/sys/kernel/debug/ieee80211'):
            if 'spectral_scan_ctl' in files:
                if os.path.exists('%s/../%s' % (dirname, netdev_dir)):
                    return dirname
        return None

    def _start_collection(self):
        fn = '%s/spectral_scan_ctl' % self.debugfs_dir
        f = open(fn, 'w')
        f.write("chanscan")
        f.close()

    def _scan(self):
        while True:
            cmd = 'iw dev %s scan' % self.interface
            if self.freqlist:
                cmd = '%s freq %s' % (cmd, ' '.join(self.freqlist))
            os.system('%s >/dev/null 2>/dev/null' % cmd)
            time.sleep(.01)

    def __init__(self, interface, freqlist=None):
        self.interface = interface
        self.freqlist = freqlist
        self.debugfs_dir = self._find_debugfs_dir()
        if not self.debugfs_dir:
            raise Exception, \
                  'Unable to access spectral_scan_ctl file for interface %s' % interface

        self.process = Process(target=self._scan, args=())

    def start(self):
        self._start_collection()
        self.process.start()

    def stop(self):
        self.process.terminate()
        self.process.join()

    def get_debugfs_dir(self):
        return self.debugfs_dir
