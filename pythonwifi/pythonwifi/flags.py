# -*- coding: utf-8 -*-
# Python WiFi -- a library to access wireless card properties via Python
# Copyright (C) 2004 - 2008 Róman Joost
# Copyright (C) 2008 - 2009 Sean Robinson
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public License
#    as published by the Free Software Foundation; either version 2.1 of
#    the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful, but
#    WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
#    USA

modes = ['Auto',
         'Ad-Hoc',
         'Managed',
         'Master',
         'Repeat',
         'Second',
         'Monitor',
         'Unknown/bug']

IFNAMSIZE = 16
IW_ESSID_MAX_SIZE = 32
IW_MAX_FREQUENCIES = 32
IW_MAX_BITRATES = 32
IW_MAX_TXPOWER = 8

SIOCGIFCONF   = 0x8912    # ifconf struct

# ioctl calls for the Linux/i386 kernel
SIOCSIWCOMMIT    = 0x8B00    # Commit pending changes to driver
SIOCGIWNAME      = 0x8B01    # get name == wireless protocol
SIOCSIWNWID      = 0x8B02    # set network id (pre-802.11)
SIOCGIWNWID      = 0x8B03    # get network id (the cell)
SIOCSIWFREQ      = 0x8B04    # set channel/frequency
SIOCGIWFREQ      = 0x8B05    # get channel/frequency
SIOCSIWMODE      = 0x8B06    # set the operation mode
SIOCGIWMODE      = 0x8B07    # get operation mode
SIOCSIWSENS      = 0x8B08    # set sensitivity (dBm)
SIOCGIWSENS      = 0x8B09    # get sensitivity
SIOCSIWRANGE     = 0x8B0A    # Unused
SIOCGIWRANGE     = 0x8B0B    # Get range of parameters
SIOCSIWPRIV      = 0x8B0C    # Unused
SIOCGIWPRIV      = 0x8B0D    # get private ioctl interface info
SIOCSIWSTATS     = 0x8B0E    # Unused
SIOCGIWSTATS     = 0x8B0F    # Get /proc/net/wireless stats
SIOCSIWSPY       = 0x8B10    # set spy addresses
SIOCGIWSPY       = 0x8B11    # get spy info (quality of link)
SIOCSIWTHRSPY    = 0x8B12    # set spy threshold (spy event)
SIOCGIWTHRSPY    = 0x8B13    # get spy threshold
SIOCSIWAP        = 0x8B14    # set AP MAC address
SIOCGIWAP        = 0x8B15    # get AP MAC addresss
SIOCGIWAPLIST    = 0x8B17    # Deprecated in favor of scanning
SIOCSIWSCAN      = 0x8B18    # set scanning off
SIOCGIWSCAN      = 0x8B19    # get scanning results
SIOCSIWESSID     = 0x8B1A    # set essid
SIOCGIWESSID     = 0x8B1B    # get essid
SIOCSIWNICKN     = 0x8B1C    # set node name/nickname
SIOCGIWNICKN     = 0x8B1D    # get node name/nickname
SIOCSIWRATE      = 0x8B20    # set default bit rate (bps)
SIOCGIWRATE      = 0x8B21    # get default bit rate (bps)
SIOCSIWRTS       = 0x8B22    # set RTS/CTS threshold (bytes)
SIOCGIWRTS       = 0x8B23    # get RTS/CTS threshold (bytes)
SIOCSIWFRAG      = 0x8B24    # set fragmentation thr (bytes)
SIOCGIWFRAG      = 0x8B25    # get fragmentation thr (bytes)
SIOCSIWTXPOW     = 0x8B26    # set transmit power (dBm)
SIOCGIWTXPOW     = 0x8B27    # get transmit power (dBm)
SIOCSIWRETRY     = 0x8B28    # set retry limits and lifetime
SIOCGIWRETRY     = 0x8B29    # get retry limits and lifetime
SIOCSIWENCODE    = 0x8B2A    # set encryption information
SIOCGIWENCODE    = 0x8B2B    # get encryption information
SIOCSIWPOWER     = 0x8B2C    # set Power Management settings
SIOCGIWPOWER     = 0x8B2D    # get power managment settings
SIOCSIWMODUL     = 0x8B2E    # set Modulations settings
SIOCGIWMODUL     = 0x8B2F    # get Modulations settings
SIOCSIWGENIE     = 0x8B30    # set generic IE
SIOCGIWGENIE     = 0x8B31    # get generic IE
# WPA
SIOCSIWMLME      = 0x8B16    # request MLME operation; uses struct iw_mlme
SIOCSIWAUTH      = 0x8B32    # set authentication mode params
SIOCGIWAUTH      = 0x8B33    # get authentication mode params
SIOCSIWENCODEEXT = 0x8B34    # set encoding token & mode
SIOCGIWENCODEEXT = 0x8B35    # get encoding token & mode
SIOCSIWPMKSA     = 0x8B36    # PMKSA cache operation

SIOCIWFIRST = 0x8B00    # FIRST ioctl identifier
SIOCIWLAST  = 0x8BFF    # LAST ioctl identifier

# Wireless events
IWEVFIRST             = 0x8C00    # FIRST event identifier
IWEVTXDROP            = 0x8C00    # Packet dropped to excessive retry
IWEVQUAL              = 0x8C01    # Quality statistics from scan
IWEVCUSTOM            = 0x8C02    # Custom Ascii string from Driver
IWEVREGISTERED        = 0x8C03    # Discovered a new node (AP mode)
IWEVEXPIRED           = 0x8C04    # Expired a node (AP mode)
IWEVGENIE             = 0x8C05    # Generic IE (WPA, RSN, WMM, ..)
IWEVMICHAELMICFAILURE = 0x8C06    # Michael MIC failure
IWEVASSOCREQIE        = 0x8C07    # IEs used in (Re)Association Request.
IWEVASSOCRESPIE       = 0x8C08    # IEs used in (Re)Association Response.
IWEVPMKIDCAND         = 0x8C09    # PMKID candidate for RSN pre-authentication
IWEVLAST              = 0x8C0A    # LAST event identifier

# Power management flags
IW_POWER_ON          = 0x0000  # No details ...
IW_POWER_TYPE        = 0xF000  # Type of parameter
IW_POWER_PERIOD      = 0x1000  # Value is a period/duration of
IW_POWER_TIMEOUT     = 0x2000  # Value is a timeout
IW_POWER_SAVING      = 0x4000  # Value is relative (how aggressive)
IW_POWER_MODE        = 0x0F00  # Power management mode
IW_POWER_UNICAST_R   = 0x0100  # Receive only unicast messages
IW_POWER_MULTICAST_R = 0x0200  # Receive only multicast messages
IW_POWER_ALL_R       = 0x0300  # Receive all messages though PM
IW_POWER_FORCE_S     = 0x0400  # Force PM procedure for sending unicast
IW_POWER_REPEATER    = 0x0800  # Repeat broadcast messages in PM period
IW_POWER_MODIFIER    = 0x000F  # Modify a parameter
IW_POWER_MIN         = 0x0001  # Value is a minimum
IW_POWER_MAX         = 0x0002  # Value is a maximum
IW_POWER_RELATIVE    = 0x0004  # Value is not in seconds/ms/us

# Retry limits and lifetime flags available
IW_RETRY_ON       = 0x0000  # No details...
IW_RETRY_TYPE     = 0xF000  # Type of parameter
IW_RETRY_LIMIT    = 0x1000  # Maximum number of retries
IW_RETRY_LIFETIME = 0x2000  # Maximum duration of retries in us
IW_RETRY_MODIFIER = 0x00FF  # Modify a parameter
IW_RETRY_MIN      = 0x0001  # Value is a minimum
IW_RETRY_MAX      = 0x0002  # Value is a maximum
IW_RETRY_RELATIVE = 0x0004  # Value is not in seconds/ms/us
IW_RETRY_SHORT    = 0x0010  # Value is for short packets
IW_RETRY_LONG     = 0x0020  # Value is for long packets

# Modes of operation
IW_MODE_AUTO    = 0   # Let the driver decides
IW_MODE_ADHOC   = 1   # Single cell network
IW_MODE_INFRA   = 2   # Multi cell network, roaming, ...
IW_MODE_MASTER  = 3   # Synchronisation master or Access Point
IW_MODE_REPEAT  = 4   # Wireless Repeater (forwarder)
IW_MODE_SECOND  = 5   # Secondary master/repeater (backup)
IW_MODE_MONITOR = 6   # Passive monitor (listen only)

# Statistics flags (bitmask in updated)
IW_QUAL_QUAL_UPDATED  = 0x01   # Value was updated since last read
IW_QUAL_LEVEL_UPDATED = 0x02
IW_QUAL_NOISE_UPDATED = 0x04
IW_QUAL_ALL_UPDATED   = 0x07
IW_QUAL_DBM           = 0x08   # Level + Noise are dBm
IW_QUAL_QUAL_INVALID  = 0x10   # Driver doesn't provide value
IW_QUAL_LEVEL_INVALID = 0x20
IW_QUAL_NOISE_INVALID = 0x40
IW_QUAL_RCPI          = 0x80   # Level + Noise are 802.11k RCPI
IW_QUAL_ALL_INVALID   = 0x70

# Frequency flags
IW_FREQ_AUTO = 0x00       # Let the driver decide
IW_FREQ_FIXED = 0x01      # Force a specific value

# Maximum number of size of encoding token available
IW_MAX_ENCODING_SIZES = 8

# Maximum size of the encoding token in bytes
IW_ENCODING_TOKEN_MAX = 64       # 512 bits (for now)

# Flags for encoding (along with the token)
IW_ENCODE_INDEX       = 0x00FF   # Token index (if needed)
IW_ENCODE_FLAGS       = 0xFF00   # Flags defined below
IW_ENCODE_MODE        = 0xF000   # Modes defined below
IW_ENCODE_DISABLED    = 0x8000   # Encoding disabled
IW_ENCODE_ENABLED     = 0x0000   # Encoding enabled
IW_ENCODE_RESTRICTED  = 0x4000   # Refuse non-encoded packets
IW_ENCODE_OPEN        = 0x2000   # Accept non-encoded packets
IW_ENCODE_NOKEY       = 0x0800   # Key is write only, so not present
IW_ENCODE_TEMP        = 0x0400   # Temporary key

# MAC address length
ETH_ALEN = 6

# constants responsible for scanning
IW_SCAN_MAX_DATA = 4096

# event sizes
IW_EV_LCP_LEN = 4
IW_EV_CHAR_LEN = IW_EV_LCP_LEN + IFNAMSIZE
IW_EV_UINT_LEN = IW_EV_LCP_LEN + 4
IW_EV_FREQ_LEN = IW_EV_LCP_LEN + 8
IW_EV_ADDR_LEN = IW_EV_LCP_LEN + 16
IW_EV_POINT_LEN = IW_EV_LCP_LEN + 4
IW_EV_PARAM_LEN = IW_EV_LCP_LEN + 8
IW_EV_QUAL_LEN = IW_EV_LCP_LEN + 4

IW_EV_LCP_PK_LEN = 4

IWHT_NULL = 0
IWHT_CHAR = 2
IWHT_UINT = 4
IWHT_FREQ = 5
IWHT_ADDR = 6
IWHT_POINT = 8
IWHT_PARAM = 9
IWHT_QUAL = 10

