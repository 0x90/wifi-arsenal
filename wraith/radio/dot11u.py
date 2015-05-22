#!/usr/bin/env python

""" dot11u 802.11u constants """
__name__ = 'dot11u'
__license__ = 'GPL v3.0'
__version__ = '0.0.1'
__date__ = 'December 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

# venue group codes type assignments Std Table 8-52 and Table 8-53 802.11u
# these are included because they may offer interesting information
VENUE_UNSPECIFIED   =  0
VENUE_ASSEMBLY      =  1
VENUE_BUSINESS      =  2
VENUE_EDUCATION     =  3
VENUE_INDUSTRIAL    =  4
VENUE_INSTITUTIONAL =  5
VENUE_MERCANTILE    =  6
VENUE_RESIDENTIAL   =  7
VENUE_STORAGE       =  8
VENUE_UTILITY       =  9
VENUE_VEHICLULAR    = 10
VENUE_OUTDOOR       = 11
VENUE_TYPE_ASSIGN = {VENUE_UNSPECIFIED:{0,"UNSPECIFIED"},
                     VENUE_ASSEMBLY:{0:"UNSPECIFIED",
                                     1:"ARENA",
                                     2:"STADIUM",
                                     3:"TERMINAL",
                                     4:"AMPITHEATER",
                                     5:"AMUSEMENT",
                                     6:"WORSHIP",
                                     7:"CONVENTION",
                                     8:"LIBRARY",
                                     9:"MUSEUM",
                                     10:"RESTAUARANT",
                                     11:"THEATER",
                                     12:"BAR",
                                     13:"COFFEE SHOP",
                                     14:"ZOO/AQUARIUM",
                                     15:"ECC"},
                     VENUE_BUSINESS:{0:"UNSPECIFIED",
                                     1:"DOCTOR",
                                     2:"BANK",
                                     3:"FIRE",
                                     4:"POLICE",
                                     6:"USPS",
                                     7:"PROFESSIONAL",
                                     8:"RD FACILITY",
                                     9:"ATTORNEY"},
                     VENUE_EDUCATION:{0:"UNSPECIFIED",
                                      1:"PRIMARY",
                                      2:"SECONDARY",
                                      3:"UNIVERSITY"},
                     VENUE_INDUSTRIAL:{0:"UNSPECIFIED",
                                       1:"FACTORY"},
                     VENUE_INSTITUTIONAL:{0:"UNSPECIFIED",
                                          1:"HOSPITAL",
                                          2:"LONG-TERM CARE",
                                          3:"REHAB",
                                          4:"GROUP HOME",
                                          5:"CORRECTIONS"},
                     VENUE_MERCANTILE:{0:"UNSPECIFIED",
                                       1:"RETAIL",
                                       2:"GROCERY",
                                       3:"AUTOMOTIVE",
                                       4:"MALL",
                                       5:"GAS STATION"},
                     VENUE_RESIDENTIAL:{0:"UNSPECIFIED",
                                        1:"PRIVATE",
                                        2:"HOTEL",
                                        3:"DORM",
                                        4:"BOARDING"},
                     VENUE_STORAGE:{0:"UNSPECIFIED"},
                     VENUE_UTILITY:{1:"UNSPECIFIED"},
                     VENUE_VEHICLULAR:{0:"UNSPECIFIED",
                                       1:"AUTOMOBILE",
                                       2:"AIRPLANE",
                                       3:"BUS",
                                       4:"FERRY",
                                       5:"SHIP",
                                       6:"TRAIN",
                                       7:"MOTORCYCLE"},
                     VENUE_OUTDOOR:{0:"UNSPECIFIED",
                                    1:"MUNI-MESH",
                                    2:"PARK",
                                    3:"REST AREA",
                                    4:"TRAFFIC CONTROL",
                                    5:"BUS STOP",
                                    6:"KIOSK"}}

