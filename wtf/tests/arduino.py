# Copyright cozybit, Inc 2010-2014
# All rights reserved

"""
Build and run/expect arduino apps
"""

import os
from random import randint
import re
from shutil import rmtree
from subprocess import Popen
from tempfile import mkdtemp
import time
import unittest

import wtf
import wtf.node.ap as ap
import wtf.node.mesh as mesh

wtfconfig = wtf.conf


class ArduinoTest(unittest.TestCase):

    """ Arduino test suite, builds, flashes, and expects. """

    @classmethod
    def setUpClass(cls):
        cls.cereal = wtfconfig.comm.serial
        cls.proc = None
        cls.env = os.environ
        cls.ffd = wtfconfig.comm.ffd
        cls.AP = wtfconfig.aps[0]

        # check for IDE path
        if 'IDE' in wtfconfig.data:
            cls.IDE = wtfconfig.data['IDE']
        else:
            cls.IDE = ''

        # set up a fake X server for a computer without one...
        if not 'DISPLAY' in cls.env or cls.env['DISPLAY'] == '':
            display = ':' + str(randint(10, 99))
            FNULL = open(os.devnull, 'w')
            cls.proc = Popen(["Xvfb", display], stdout=FNULL, stderr=FNULL)
            cls.env['DISPLAY'] = display

    @classmethod
    def tearDownClass(cls):
        # if we had to change the display, set it back and kill fake x server
        if cls.proc:
            cls.proc.kill()

    def setUp(self):
        # validate the IDE path is a directory, and the arduino file exists
        # inside of it
        if not os.path.isdir(self.IDE) or not os.path.isfile(self.IDE + '/arduino'):
            self.fail(
                    'There was a problem with the IDE supplied in the wtfconfig.py')
        # make a temp file to build an arduino sketch in
        self.build_dir = mkdtemp()

        """ flush before every test to clear serial buffer """
        self.cereal.setTimeout(0)
        self.cereal.readall()
        self.cereal.flushInput()
        self.cereal.flushOutput()
        self.cereal.flush()

    def tearDown(self):
        if os.path.exists(self.build_dir) and os.path.isdir(self.build_dir):
            rmtree(self.build_dir)
        self.build_dir = None

    def build_and_upload(self, build_path):
        back = os.getcwd()
        try:
            os.chdir(self.IDE)
        except OSError:
            self.fail("You do not have the correct arduino ide directory path set")

        ret = Popen(["./arduino", "--upload", "--board",
                "cozybit:mc200:mc200_dbg", "-v", "--pref",
                "build.path=" + self.build_dir, "--port", self.cereal.port,
                build_path], env=self.env)
        ret.wait()
        self.failIf(ret.returncode, "There was a problem while building and"
                "uploading %s a return value of %d was given" %
                (build_path, ret.returncode))
        os.chdir(back)

    def setup_run(self, path, write=None):
        self.build_and_upload(path)
        if write:
            self.cereal.write(write)

    def start_hostapd(self, apconf):
        """ Set hostap.conf and init/start node """
        self.AP.config = apconf
        self.AP.init()
        self.AP.start()
        time.sleep(5)

    def stop_hostapd(self):
        self.AP.stop()

    def test_01_string_addition_operators(self):
        self.setup_run('./examples/08.Strings/StringAdditionOperator/'
                'StringAdditionOperator.ino')
        self.ffd.expect(re.escape('stringThree = 123'))
        self.ffd.expect(re.escape('stringThree = 123456789'))
        self.ffd.expect(re.escape('stringThree = A'))
        self.ffd.expect(re.escape('stringThree = abc'))
        self.ffd.expect(re.escape('stringThree = this string'))
        self.ffd.expect(re.escape('Sensor value: ') + r'\d+')
        self.ffd.expect(re.escape('millis() value: ') + r'\d+')

    def test_02_string_replace(self):
        self.setup_run("./examples/08.Strings/StringReplace/StringReplace.ino")
        self.ffd.expect(re.escape('<html><head><body>'))
        self.ffd.expect(
                re.escape('Original string: <html><head><body>'))
        self.ffd.expect(
                re.escape('Modified string: </html></head></body>'))
        self.ffd.expect(re.escape('normal: bookkeeper'))
        self.ffd.expect(re.escape('l33tspeak: b00kk33p3r'))

    def test_03_ascii_table(self):
        # set timeout since this has a lot to print and 0 timeout doesnt read it
        self.cereal.setTimeout(1)
        self.setup_run("./examples/04.Communication/ASCIITable/ASCIITable.ino")
        self.ffd.expect(
                re.escape('(, dec: 40, hex: 28, oct: 50, bin: 101000'))
        self.ffd.expect(
                re.escape('8, dec: 56, hex: 38, oct: 70, bin: 111000'))
        self.ffd.expect(
                re.escape('A, dec: 65, hex: 41, oct: 101, bin: 1000001'))
        self.ffd.expect(
                re.escape('\, dec: 92, hex: 5C, oct: 134, bin: 101110'))
        self.ffd.expect(
                re.escape('z, dec: 122, hex: 7A, oct: 172, bin: 1111010'))

    def test_04_character_analysis(self):
        self.setup_run(
                "./examples/08.Strings/CharacterAnalysis/CharacterAnalysis.ino",
                write='aB12!@')
        self.ffd.expect(
                re.escape("You sent me: 'a'  ASCII Value: 97"))
        self.ffd.expect(
                re.escape("You sent me: 'B'  ASCII Value: 66"))
        self.ffd.expect(
                re.escape("You sent me: '1'  ASCII Value: 49"))
        self.ffd.expect(
                re.escape("You sent me: '2'  ASCII Value: 50"))
        self.ffd.expect(
                re.escape("You sent me: '!'  ASCII Value: 33"))
        self.ffd.expect(
                re.escape("You sent me: '@'  ASCII Value: 64"))

    def test_05_string_append_operator(self):
        self.setup_run(
                "./examples/08.Strings/StringAppendOperator/StringAppendOperator.ino")
        self.ffd.expect(
                re.escape('Sensor value for input A0: ') + r'\d+')
        self.ffd.expect(re.escape('A long integer: 123456789'))
        self.ffd.expect(re.escape('The millis(): ') + r'\d+')

    def test_06_string_case_changes(self):
        self.setup_run(
                "./examples/08.Strings/StringCaseChanges/StringCaseChanges.ino")
        self.ffd.expect(re.escape('<html><head><body>'))
        self.ffd.expect(re.escape('<HTML><HEAD><BODY>'))
        self.ffd.expect(re.escape('</BODY></HTML>'))
        self.ffd.expect(re.escape('</body></html>'))

    def test_07_string_characters(self):
        self.setup_run(
                "./examples/08.Strings/StringCharacters/StringCharacters.ino")
        self.ffd.expect(
                re.escape('Most significant digit of the sensor reading is: 4'))
        self.ffd.expect(re.escape('SensorReading= 456'))

    def test_08_string_constructors(self):
        self.setup_run(
                "./examples/08.Strings/StringConstructors/StringConstructors.ino")
        self.ffd.expect(re.escape('Hello String'))
        self.ffd.expect(re.escape('This is a string'))
        self.ffd.expect(re.escape('This is a string with more'))
        self.ffd.expect(re.escape('2d'))
        self.ffd.expect(re.escape('11111111'))

    def test_09_index_of(self):
        self.setup_run(
                "./examples/08.Strings/StringIndexOf/StringIndexOf.ino")
        self.ffd.expect(
                re.escape('The index of > in the string <HTML><HEAD><BODY> is 5'))
        self.ffd.expect(
                re.escape('The index of  the second > in the string <HTML><HEAD><BODY> is 11'))
        self.ffd.expect(
                re.escape('The index of the body tag in the string <HTML><HEAD><BODY> is 12'))
        self.ffd.expect(
                re.escape('The index of the last < in the string <UL><LI>item<LI>item<LI>item</UL> is 28'))

    def test_10_string_length(self):
        self.setup_run("./examples/08.Strings/StringLength/StringLength.ino",
                write='h' * 100 + '\r' + 'f' * 100 + '\r')
        self.ffd.expect(re.escape('101'))
        self.ffd.expect(re.escape('acceptable text message'))
        self.ffd.expect(re.escape('202'))
        self.ffd.expect(
                re.escape('too long for a text message.'))

    def test_11_string_length_trim(self):
        self.setup_run(
                "./examples/08.Strings/StringLengthTrim/StringLengthTrim.ino")
        self.ffd.expect(
                re.escape('Hello!       <--- end of string. Length: 13'))
        self.ffd.expect(
                re.escape('Hello!<--- end of trimmed string. Length: 6'))

    def test_12_string_starts_with_ends_with(self):
        self.setup_run(
                "examples/08.Strings/StringStartsWithEndsWith/StringStartsWithEndsWith.ino")
        self.ffd.expect(re.escape('HTTP/1.1 200 OK'))
        self.ffd.expect(re.escape("Server's using http version 1.1"))
        self.ffd.expect(re.escape('Got an OK from the server'))
        self.ffd.expect(re.escape('sensor = ') + r'\d+' +
                re.escape('. This reading is ') + r'(not )?' +
                re.escape('divisible by ten'))

    def test_13_string_substring(self):
        self.setup_run("./examples/08.Strings/StringSubstring/StringSubstring.ino")
        self.ffd.expect(re.escape('Content-Type: text/html'))
        self.ffd.expect(re.escape("It's an html file"))
        self.ffd.expect(re.escape("It's a text-based file"))

    def test_14_string_to_int(self):
        self.setup_run("./examples/08.Strings/StringToInt/StringToInt.ino",
                write="123\r55\rasdf\r85a8\r")
        self.ffd.expect(re.escape('Value:123'))
        self.ffd.expect(re.escape('String: 123'))
        self.ffd.expect(re.escape('Value:55'))
        self.ffd.expect(re.escape('String: 55'))
        self.ffd.expect(re.escape('Value:0'))
        self.ffd.expect(re.escape('String: \n'))
        self.ffd.expect(re.escape('Value:858'))
        self.ffd.expect(re.escape('String: 858'))

    def test_15_connect_wifi_no_password(self):
        self.start_hostapd(ap.APConfig(ssid="wtf-arduino-ap"))
        self.setup_run(os.getcwd() + '/platform/arduino/SimpleWiFi/SimpleWiFi.ino')
        # set to 20 incase connection takes longer than 10 seconds
        time.sleep(20)
        self.ffd.expect(re.escape("You're connected to the network"));
        # [1-9] first so we don't match 0.0.0.0 with d+.d+.d+.d+
        self.ffd.expect(re.escape("the ip is ") + r'[1-9]\d+\.\d+\.\d+\.\d+')
        self.stop_hostapd()

    def test_16_connect_wifi_with_password(self):
        self.start_hostapd(ap.APConfig(ssid="wtf-arduino-pass-ap",
                security=ap.SECURITY_WPA2,
                auth=ap.AUTH_PSK,
                password="thisisasecret",
                encrypt=ap.ENCRYPT_CCMP))
        self.setup_run(os.getcwd() + '/platform/arduino/SimpleWiFiPass/SimpleWiFiPass.ino')
        # set to 20 incase connection takes longer than 10 seconds
        time.sleep(20)
        self.ffd.expect(re.escape("You're connected to the password protected network"));
        # [1-9] first so we don't match 0.0.0.0 with d+.d+.d+.d+
        self.ffd.expect(re.escape("the ip is ") + r'[1-9]\d+\.\d+\.\d+\.\d+')
        self.stop_hostapd()
