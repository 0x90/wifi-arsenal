# Author: Tomasz bla Fortuna
# License: GPLv2

import os
import sys
import traceback
from time import time, sleep
import threading

class WatchDog(threading.Thread):
    "Internal watchdog"

    def __init__(self, interval=10):
        super(WatchDog, self).__init__()

        self.interval = interval
        self.stamp = None
        self.setDaemon(True)
        self.start()

    def dontkillmeplease(self):
        self.stamp = time()

    def run(self):
        self.dontkillmeplease()
        last_check = time()
        while True:
            sleep(self.interval)
            now = time()
            if self.stamp + self.interval < now:
                if now - last_check > 2 * self.interval:
                    print "Watchdog: Hibernation/suspend/global lock detected - still waiting."
                    last_check = now
                    continue # Wait one interval more
                self.die()
            last_check = now


    def die(self):
        "Kill process"
        print "=========== WATCHDOG ==========="
        print "Process was idle for %d seconds." % self.interval
        print "================================"
        self._dump_stacktraces()
        os.kill(os.getpid(), 9)

    def _dump_stacktraces(self):
        lines = []
        this_frame = sys._getframe()
        for thread_id, frame in sys._current_frames().iteritems():
            if frame == this_frame:
                continue # Ignore watchdog frame
            lines.append("")
            lines.append("# Thread ID: %s" % thread_id)
            lines += [line.strip()
                      for line in traceback.format_stack(frame)]

        lines += ["", "Watchdog salutes.", "================================"]
        print >> sys.stderr, "\n".join(lines)
