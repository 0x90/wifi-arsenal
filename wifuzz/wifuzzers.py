# Copyright notice
# ================
#
# Copyright (C) 2011
#     Roberto  Paleari    <roberto.paleari@gmail.com>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# WiFuzz is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.

from scapy.layers.dot11 import *
from scapy.layers.l2    import *

from common  import log

WIFI_STATE_NONE          = 0
WIFI_STATE_PROBED        = 1
WIFI_STATE_AUTHENTICATED = 2
WIFI_STATE_ASSOCIATED    = 3

def state_to_name(s):
    if   s == WIFI_STATE_NONE:          n = "none"
    elif s == WIFI_STATE_PROBED:        n = "probed"
    elif s == WIFI_STATE_AUTHENTICATED: n = "authenticated"
    elif s == WIFI_STATE_ASSOCIATED:    n = "associated"
    return n

class WifiFuzzer:
    state = WIFI_STATE_NONE

    """The WifiFuzzer class is the parent of all the fuzzers."""
    def __init__(self, driver):
        self.driver = driver

    def _preconditions(self):
        """This method is invoked by the fuzzer driver before sending out the
        fuzzed packets, but after the target 802.11 state has been
        reached. Concrete fuzzer instances should use this function to enforce
        additional checks before allowing packets to go out (e.g., wait for
        packets from the AP)."""
        return

    def genPackets(self):
        abstract()

    def log(self, msg):
        """Log a debug message."""
        log(msg, module = "FUZZ")

    @staticmethod
    def getName(): 
        abstract()

    def fuzz(self):
        # Move into the target 802.11 state...
        if self.state == WIFI_STATE_PROBED:
            self.driver.probe()
        elif self.state == WIFI_STATE_AUTHENTICATED:
            self.driver.authenticate()
        elif self.state == WIFI_STATE_ASSOCIATED:
            self.driver.associate()

        # ...check for preconditions...
        self._preconditions()

        # ...and fuzz!
        for p in self.genPackets():
            self.driver.send(p)

class WifiFuzzerAny(WifiFuzzer):
    """Random 802.11 frame fuzzer."""

    def genPackets(self):
        return [RadioTap()/fuzz(Dot11()), ]

    @staticmethod
    def getName():
        return "any"

class WifiFuzzerBeacon(WifiFuzzer):
    """Beacon request fuzzer."""

    def genPackets(self):
        return [RadioTap()/Dot11()/fuzz(Dot11Beacon()), ]

    @staticmethod
    def getName():
        return "beacon"

class WifiFuzzerAssoc(WifiFuzzer):
    """Association request fuzzer."""
    state = WIFI_STATE_AUTHENTICATED

    def genPackets(self):
        return [RadioTap()/Dot11()/fuzz(Dot11AssoReq()), ]

    @staticmethod
    def getName():
        return "assoc"

class WifiFuzzerDessoc(WifiFuzzer):
    """Deassociation request fuzzer."""
    state = WIFI_STATE_ASSOCIATED

    def genPackets(self):
        return [RadioTap()/Dot11()/fuzz(Dot11Disas()), ]

    @staticmethod
    def getName():
        return "deassoc"

class WifiFuzzerAuth(WifiFuzzer):
    """Authentication request fuzzer."""
    state = WIFI_STATE_PROBED

    def genPackets(self):
        return [RadioTap()/Dot11()/fuzz(Dot11Auth()), ]

    @staticmethod
    def getName():
        return "auth"

class WifiFuzzerDeauth(WifiFuzzer):
    """Deauthentication request fuzzer."""
    state = WIFI_STATE_AUTHENTICATED

    def genPackets(self):
        return [RadioTap()/Dot11()/fuzz(Dot11Deauth()), ]

    @staticmethod
    def getName():
        return "deauth"

class WifiFuzzerProbe(WifiFuzzer):
    """Probe request fuzzer."""

    def genPackets(self):
        return [RadioTap()/Dot11()/fuzz(Dot11ProbeReq())/Dot11Elt(ID='SSID',info=self.driver.ssid)/fuzz(Dot11Elt(ID='Rates')), ]

    @staticmethod
    def getName():
        return "probe"

class WifiFuzzerEAP(WifiFuzzer):
    """EAP protocol fuzzer."""
    state = WIFI_STATE_ASSOCIATED

    def genPackets(self):
        p = RadioTap()/Dot11(FCfield="to-DS")/LLC()/SNAP()/fuzz(EAP())
        return [p, ]
    
    @staticmethod
    def getName():
        return "eap"

class WifiFuzzerEAPOL(WifiFuzzer):
    """EAPOL (EAP-over-LAN) protocol fuzzer."""
    state = WIFI_STATE_ASSOCIATED

    def genPackets(self):
        # EAPOL version
        if random.randint(1, 4) != 1:
            # Use a valid EAPOL version with 0.75 probability
            version = random.randint(1, 2)
        else:
            version = random.randint(0, 255)

        # EAPOL packet type
        if random.randint(1, 4) != 1:
            # Use a valid EAPOL packet type with 0.75 probability
            typez = random.choice(["EAP_PACKET", "START", "LOGOFF", "KEY", "ASF"])
        else:
            typez = random.randint(0, 255)

        # Make a random body, leave it empty with 0.5 probability. At this
        # layer we have only 1470 bytes left for the body
        if random.randint(1,2) == 1:
            bodylen = 0
        else:
            bodylen = random.randint(1, 1470)

        body = "".join([chr(random.randint(0,255)) for i in range(bodylen)])

        p = RadioTap()/Dot11(FCfield="to-DS")/LLC()/SNAP()/EAPOL(version = version, type = typez, len = bodylen)
        if bodylen > 0:
            p /= Raw(load = body)

        return [p, ]
    
    @staticmethod
    def getName():
        return "eapol"
