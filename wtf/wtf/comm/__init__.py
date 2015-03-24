# Copyright cozybit, Inc 2010-2011
# All rights reserved

import serial
import fdpexpect
import pxssh
import commands
import subprocess
import time

from wtf.util import get_adb_id


class CommandFailureError(Exception):

    """
    Exception raised when a comm fails to send a command.
    """
    pass


class CommBase():

    """
    A command communication channel

    wtf needs a way to pass commands to nodes, retrieve return codes, and
    retrieve output.
    """
    verbosity = 0
    name = ""

    def __init__(self):
        pass

    def send_cmd(self, command, verbosity=None):
        """
        Send a command via this comm channel

        return a tuple containing the return code and the stdout lines

        override the default verbosity for the command being sent by setting
        the verbosity argument.

        raise a CommandFailureError if it was not possible to send the command.

        Implementors of new comm subclasses can either override send_cmd, or
        implement _send_cmd() to send a command and return the stdout, and
        _get_retcode() to get the return code of the last command.
        """
        if verbosity is None:
            verbosity = self.verbosity
        elif verbosity > self.verbosity:
            verbosity = self.verbosity
        if verbosity > 0:
            print self.name + ": " + command
        output = self._send_cmd(command)
        if verbosity > 1:
            for l in output:
                print self.name + ": " + l
        r = self._get_retcode()
        return (r, output)

    def reboot(self):
        raise NotImplementedError()


class Serial(CommBase):

    """
    Communicate with a node via a serial port

    The console on the other end must at least be able to 'echo $?' so we can
    get the return code.
    """

    def __init__(self, port="/dev/ttyUSB0", baudrate=115200,
                 prompt="[root@localhost]# "):
        self.serial = serial.Serial(port, baudrate, timeout=1)
        self.serial.flushInput()
        self.serial.flushOutput()
        self.ffd = fdpexpect.fdspawn(self.serial.fd)
        self.prompt = prompt
        # assume that because we flushed, we are at a bare prompt
        CommBase.__init__(self)

    def __del__(self):
        self.serial.flushInput()
        self.serial.flushOutput()
        self.serial.close()

    def _send_cmd(self, command):
        self.ffd.send("%s\n" % command)
        r = self.ffd.expect_exact([self.prompt, fdpexpect.TIMEOUT])
        # Sometimes a long command line will be wrapped by pyserial.  This
        # causes problems where the tail end of the command line gets garbled
        # into the response.
        output = self.ffd.before.replace("\r\r\n", "")
        output = output.split("\r\n")[1:-1]
        if r == 1:
            return ""
        return output

    def _get_retcode(self):
        self.ffd.send("echo $?\n")
        r = self.ffd.expect_exact([self.prompt, fdpexpect.TIMEOUT])
        if r == 1:
            return -1
        try:
            return int(self.ffd.before.split("\r\n")[-2])
        except ValueError:
            print self.ffd.before
            raise CommandFailureError("Failed to find return code in stdout")
        return -1


class ADB(CommBase):

    """
    Communicate with a node via adb
    """

    def __init__(self, device_id):
        self._device_id = device_id
        self._adb_id = get_adb_id(self._device_id)
        self._init_session()
        CommBase.__init__(self)

    def _init_session(self):
        adb_log_fp = open("wtf.adb.log", "w")
        self.session = pxssh.pxssh(logfile=adb_log_fp)
        self.session.adbLogin(self._device_id)

    def _send_cmd(self, command):
        # TODO: Okay.  Here's a mystery.  If the command is 69 chars long,
        # pxssh chokes on whatever it sees over ssh and all subsequent tests
        # fail.  Amazing!  If it's longer, or shorter, everything works fine.
        # But the magic number 69 breaks the command flow.  Why?  Could it be
        # that the prompt "[PEXPECT]# " is 11 chars, and 69 + 11 is 80, and
        # there's a line discipline problem somewhere?  If you figure it out
        # you'll be my hero.
        if len(command) == 69:
            command = "  " + command
        self.session.sendline(command)
        # maybe we want to block on command completion...
        self.session.PROMPT = r"[a-z]+@[a-z]+:.*[\$\#]"
        # for some reason shell variables need an extra prompt call to be
        # expanded
        self.session.prompt(timeout=300)
        output = self.session.before.split("\r\n")[1:-1]
        # take out return carriage which is the last character still...
        for i in range(0, len(output)):
            output[i] = output[i][0:-1]
        return output

    def get_device_id(self):
        return self._device_id

    def get_adb_id(self):
        return self._adb_id

    def reboot(self):
        retcode = subprocess.call(["adb", "-s", self.get_adb_id(), "reboot"])
        if retcode != 0:
            raise StandardError("Command 'reboot' via adb failed")
        retcode = subprocess.call(["adb", "-s", self.get_adb_id(),
                                   "wait-for-device"])
        if retcode != 0:
            raise StandardError("Command 'wait-for-device' via adb failed")
        time.sleep(1)
        self._init_session()

    def _get_retcode(self):
        self.session.sendline("echo $?")
        self.session.prompt()
        try:
            if len(self.session.before.split("\n")) > 2:
                return int(self.session.before.split("\n")[-2])
            return 0
        except ValueError:
            print "Failed to find return code in:"
            print self.session.before
            # try to recover
            self.session.synch_original_prompt()
        return -1

    # should be able to use existing SSH session for this
    # XXX: GARBAGE! Should really be handled by the ssh module
    # copy file from host:$src to $dst
    def get_file(self, src, dst):
        print "copying %s:%s to %s" % (self.name, src, dst)
        r, o = commands.getstatusoutput(
            "scp root@%s:%s %s" % (self.ipaddr, src, dst))
        if r != 0:
            raise StandardError("couldn't copy file: %s to %s \n %s" %
                                (src, dst, o))

    def put_file(self, src, dst):
        print "copying %s to %s:%s" % (src, self.name, dst)
        r, o = commands.getstatusoutput(
            "rsync %s root@%s:%s" % (src, self.ipaddr, dst))
        if r != 0:
            raise StandardError("couldn't copy file: %s to %s \n %s" %
                                (src, dst, o))


class SSH(CommBase):

    """
    communicate with a node via ssh

    The console on the other end must at least be able to 'echo $?' so we can
    get the return code.
    """

    def __init__(self, ipaddr, user="root"):
        self.session = pxssh.pxssh()
        self.session.login(ipaddr, user)
        self.ipaddr = ipaddr
        CommBase.__init__(self)

    # XXX: WARNING! _send_cmd() won't ever block for more than 5 minutes, see
    # the session.prompt() call below.
    def _send_cmd(self, command):
        # TODO: Okay.  Here's a mystery.  If the command is 69 chars long,
        # pxssh chokes on whatever it sees over ssh and all subsequent tests
        # fail.  Amazing!  If it's longer, or shorter, everything works fine.
        # But the magic number 69 breaks the command flow.  Why?  Could it be
        # that the prompt "[PEXPECT]# " is 11 chars, and 69 + 11 is 80, and
        # there's a line discipline problem somewhere?  If you figure it out
        # you'll be my hero.
        if len(command) == 69:
            command = "  " + command
        self.session.sendline(command)
        # maybe we want to block on command completion...
        self.session.prompt(timeout=300)
        output = self.session.before.split("\r\n")[1:-1]
        return output

    def _get_retcode(self):
        self.session.sendline("echo $?")
        self.session.prompt()
        try:
            return int(self.session.before.split("\n")[-2])
        except ValueError:
            print "Failed to find return code in:"
            print self.session.before
            # try to recover
            self.session.synch_original_prompt()
        return -1

    # should be able to use existing SSH session for this
    # XXX: GARBAGE! Should really be handled by the ssh module
    # copy file from host:$src to $dst
    def get_file(self, src, dst):
        print "copying %s:%s to %s" % (self.name, src, dst)
        r, o = commands.getstatusoutput(
            "scp root@%s:%s %s" % (self.ipaddr, src, dst))
        if r != 0:
            raise StandardError("couldn't copy file: %s to %s \n %s" %
                                (src, dst, o))

    def put_file(self, src, dst):
        print "copying %s to %s:%s" % (src, self.name, dst)
        r, o = commands.getstatusoutput(
            "rsync %s root@%s:%s" % (src, self.ipaddr, dst))
        if r != 0:
            raise StandardError("couldn't copy file: %s to %s \n %s" %
                                (src, dst, o))


class MvdroidSerial(Serial):

    """
    communicate with an mvdroid device via a serial port

    The mvdroid serial console has some nuances that require special setup.
    For example, many of the utilities that wft needs are available in
    non-standard places.  Also, the console printks are pretty loud and must be
    silenced.
    """

    def __init__(self, port="/dev/ttyUSB0", baudrate=115200, prompt="# "):
        Serial.__init__(self, port, baudrate, prompt)
        self.send_cmd("busybox sh", verbosity=2)
        self.send_cmd("echo 0 > /proc/sys/kernel/printk")
        self.send_cmd("export PATH=/marvell/tel:$PATH")
        self.send_cmd("cd /marvell/tel/")
        self.send_cmd("mount -o remount,rw /dev/block/mtdblock11 /marvell")
        busybox_cmds = ["ifconfig", "rm",
                        "mkdir", "killall", "grep", "rmdir"]
        for c in busybox_cmds:
            self.send_cmd("ln -s busybox " + c)
