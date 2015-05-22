from unittest import TestCase

from wifi.scan import Cell
from wifi.exceptions import InterfaceError


class IWListParserTest(TestCase):
    def test_no_encryption(self):
        cell = Cell.from_string(IWLIST_SCAN_NO_ENCRYPTION)
        self.assertFalse(cell.encrypted)
        self.assertEqual(cell.ssid, 'My Wireless Network')
        self.assertEqual(cell.signal, -51)
        self.assertEqual(cell.quality, '59/70')
        self.assertEqual(cell.frequency, '2.437 GHz')
        self.assertEqual(cell.mode, 'Master')
        self.assertEqual(cell.channel, 6)

    def test_wep(self):
        cell = Cell.from_string(IWLIST_SCAN_WEP)
        self.assertTrue(cell.encrypted)
        self.assertEqual(cell.encryption_type, 'wep')

    def test_wpa2(self):
        cell = Cell.from_string(IWLIST_SCAN_WPA2)
        self.assertTrue(cell.encrypted)
        self.assertEqual(cell.encryption_type, 'wpa2')

    def test_wpa1(self):
        cell = Cell.from_string(IWLIST_SCAN_WPA1)
        self.assertTrue(cell.encrypted)
        self.assertEqual(cell.encryption_type, 'wpa')

    def test_alternative_iwlist_output(self):
        # https://github.com/rockymeza/wifi/issues/12
        cell = Cell.from_string(ALTERNATIVE_OUTPUT)
        self.assertEqual(cell.quality, '78/100')
        self.assertEqual(cell.signal, -92)

    def test_signal_level_out_of_sixty(self):
        cell = Cell.from_string(ALTERNATIVE_OUTPUT2)
        self.assertEqual(cell.signal, -71)

    def test_noname_cell(self):
        cell = Cell.from_string(NONAME_WIRELESS_NETWORK)
        self.assertEqual(cell.ssid, '')

    def test_no_channel_output(self):
        # https://github.com/rockymeza/wifi/issues/24
        cell = Cell.from_string(NO_CHANNEL_OUTPUT)
        self.assertEqual(cell.channel, 11)

    def test_list_index_error(self):
        # https://github.com/rockymeza/wifi/issues/42
        cell = Cell.from_string(LIST_INDEX_ERROR)

    def test_frequency_no_channel_output(self):
        # https://github.com/rockymeza/wifi/issues/39
        cell = Cell.from_string(FREQUENCY_NO_CHANNEL_OUTPUT)
        self.assertEqual(cell.channel, 149)

    def test_absolute_quality(self):
        # https://github.com/rockymeza/wifi/pull/45
        cell = Cell.from_string(ABSOLUTE_QUALITY)
        self.assertEqual(cell.quality, '38/100')
        self.assertEqual(cell.signal, -92)


class ScanningTest(TestCase):
    def test_scanning(self):
        self.assertRaises(InterfaceError, Cell.all, 'fake-interface')


IWLIST_SCAN_NO_ENCRYPTION = """Cell 02 - Address: 38:83:45:CC:58:74
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=59/70  Signal level=-51 dBm  
                    Encryption key:off
                    ESSID:"My Wireless Network"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00000079fc961317
                    Extra: Last beacon: 60ms ago
                    IE: Unknown: 001754502D4C494E4B5F506F636B657441505F434335383734
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030106
                    IE: Unknown: 0706555320010D14
                    IE: Unknown: 2A0100
                    IE: Unknown: 32043048606C
                    IE: Unknown: 2D1A6E1003FF00000000000000000000000000000000000000000000
                    IE: Unknown: 331A6E1003FF00000000000000000000000000000000000000000000
                    IE: Unknown: 3D1606051100000000000000000000000000000000000000
                    IE: Unknown: 341606051100000000000000000000000000000000000000
                    IE: Unknown: DD180050F2020101010003A4000027A4000042435E0062322F00
                    IE: Unknown: DD0900037F01010000FF7F
"""

IWLIST_SCAN_WEP = """Cell 01 - Address: 00:21:27:35:1B:E8
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=36/70  Signal level=-74 dBm  
                    Encryption key:on
                    ESSID:"WEP Network"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              12 Mb/s; 24 Mb/s; 36 Mb/s
                    Bit Rates:9 Mb/s; 18 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00000022fa7f11cd
                    Extra: Last beacon: 60ms ago
                    IE: Unknown: 00025348
                    IE: Unknown: 010882848B960C183048
                    IE: Unknown: 030106
                    IE: Unknown: 0706434E20010D14
                    IE: Unknown: 2A0100
                    IE: Unknown: 32041224606C
                    IE: Unknown: DD0900037F01010008FF7F
                    IE: Unknown: DD1A00037F0301000000002127351BE8022127351BE864002C010808
"""

IWLIST_SCAN_WPA2 = """Cell 08 - Address: 00:22:B0:98:5E:77
                    Channel:1
                    Frequency:2.412 GHz (Channel 1)
                    Quality=42/70  Signal level=-68 dBm  
                    Encryption key:on
                    ESSID:"WPA2 network"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 9 Mb/s
                              18 Mb/s; 36 Mb/s; 54 Mb/s
                    Bit Rates:6 Mb/s; 12 Mb/s; 24 Mb/s; 48 Mb/s
                    Mode:Master
                    Extra:tsf=000000029170ed29
                    Extra: Last beacon: 24ms ago
                    IE: Unknown: 00096265616E7472656531
                    IE: Unknown: 010882848B961224486C
                    IE: Unknown: 030101
                    IE: Unknown: 2A0100
                    IE: Unknown: 32040C183060
                    IE: Unknown: 2D1A6E1013FFFF0000010000000000000000000000000C0000000000
                    IE: Unknown: 3D1601050700000000000000000000000000000000000000
                    IE: Unknown: 3E0100
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (1) : TKIP
                        Authentication Suites (1) : PSK
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (1) : TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: DD180050F2020101000003A4000027A4000042435E0062322F00
                    IE: Unknown: 7F0101
                    IE: Unknown: DD07000C4304000000
                    IE: Unknown: 0706474220010D10
                    IE: Unknown: DD1E00904C336E1013FFFF0000010000000000000000000000000C0000000000
                    IE: Unknown: DD1A00904C3401050700000000000000000000000000000000000000
                    IE: Unknown: DD050050F20500
                    IE: Unknown: DD750050F204104A00011010440001021041000100103B00010310470010C59BF13CE0C57AA1476C0022B0985E7710210006442D4C696E6B102300074449522D363035102400074449522D3630351042000830303030303030301054000800060050F2040001101100074449522D36303510080002008E
"""

IWLIST_SCAN_WPA1 = """Cell 01 - Address: 
                    ESSID:
                    Protocol:IEEE 802.11bg
                    Mode:Master
                    Frequency:2.457 GHz (Channel 10)
                    Encryption key:on
                    Bit Rates:54 Mb/s
                    Extra:wpa_ie=dd160050f20101000050f20201000050f20201000050f202
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (1) : TKIP
                        Authentication Suites (1) : PSK
                    Quality=100/100  Signal level=74/100  
"""

ALTERNATIVE_OUTPUT = """Cell 06 - Address: F2:23:DB:A3:3B:A0
                    ESSID:"Antons iPhone"
                    Protocol:IEEE 802.11g
                    Mode:Master
                    Frequency:2.412 GHz (Channel 1)
                    Encryption key:on
                    Bit Rates:54 Mb/s
                    Extra:rsn_ie=30140100000fac040100000fac040100000fac020c00
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    Quality=78/100  Signal level=16/100
"""

ALTERNATIVE_OUTPUT2 = """Cell 06 - Address: F2:23:DB:A3:3B:A0
                    ESSID:"Antons iPhone"
                    Protocol:IEEE 802.11g
                    Mode:Master
                    Frequency:2.412 GHz (Channel 1)
                    Encryption key:on
                    Bit Rates:54 Mb/s
                    Extra:rsn_ie=30140100000fac040100000fac040100000fac020c00
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    Quality=78/100  Signal level=35/60
"""

NONAME_WIRELESS_NETWORK = """Cell 01 - Address: A4:56:30:E8:97:F0
                    ESSID:""
                    Protocol:IEEE 802.11gn
                    Mode:Master
                    Frequency:2.437 GHz (Channel 6)
                    Encryption key:on
                    Bit Rates:144 Mb/s
                    Extra:wpa_ie=dd1c0050f20101000050f20202000050f2020050f20401000050f2020000
                    IE: WPA Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : TKIP CCMP
                        Authentication Suites (1) : PSK
                    Extra:rsn_ie=30180100000fac020200000fac02000fac040100000fac022800
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : TKIP CCMP
                        Authentication Suites (1) : PSK
                    Quality=84/100  Signal level=43/100  
"""

NO_CHANNEL_OUTPUT = """Cell 06 - Address: 
                    ESSID:
                    Protocol:IEEE 802.11bgn
                    Mode:Master
                    Frequency:2.462 GHz (Channel 11)
                    Encryption key:on
                    Bit Rates:144 Mb/s
                    Extra:rsn_ie=30140100000fac040100000fac040100000fac020c00
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    Quality=93/100  Signal level=10/100 
"""

LIST_INDEX_ERROR = """Cell 04 - Address: 50:06:04:C3:4D:93
                    Protocol:11g/n BW20
                    ESSID:""
                    Mode:Managed
                    Frequency:2.412 GHz (Channel 1)
                    Quality=94/100  Signal level=-53 dBm  Noise level=-92 dBm
                    Encryption key:off
                    Bit Rates:144 Mb/s
"""

FREQUENCY_NO_CHANNEL_OUTPUT = """Cell 01 - Address: 58:6D:8F:2B:DA:8E
                    Channel:149
                    Frequency:5.745 GHz
                    Quality=65/70 Signal level=-45 dBm
                    Encryption key:on
                    ESSID:"3408TT"
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 18 Mb/s; 24 Mb/s
                    36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=0000000edea58e3a
                    Extra: Last beacon: 140ms ago
                    IE: Unknown: 0006333430385454
                    IE: Unknown: 01088C129824B048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 2D1AEE081AFFFF000001000000000000000000000000000000000000
                    IE: Unknown: 3D16950D0000000000000000000000000000000000000000
                    IE: Unknown: DD090010180200F02C0000
                    IE: Unknown: DD180050F2020101800003A4000027A4000042435E0062322F00
"""

ABSOLUTE_QUALITY = """Cell 04 - Address: 50:06:04:C3:4D:93
                    Protocol:11g/n BW20
                    ESSID:""
                    Mode:Managed
                    Frequency:2.412 GHz (Channel 1)
                    Quality:38 Signal level:16 Noise level:0
                    Encryption key:off
                    Bit Rates:144 Mb/s
"""
