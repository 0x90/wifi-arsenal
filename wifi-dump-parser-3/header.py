#Author : Abhinav Narain 
#Date : 14 Jan,2013 
#Purpose : header file defining all the constants used c structs used 
# File belongs to part of Data Parsing Library

IEEE80211_TX_RC_USE_SHORT_PREAMBLE  = 1<< 2
IEEE80211_TX_RC_40_MHZ_WIDTH        = 1<< 5
IEEE80211_TX_RC_SHORT_GI            = 1<< 7


T_MGMT =0x0  # management 
T_CTRL =0x1  # control 
T_DATA =0x2  # data 

CTRL_CONTROL_WRAPPER =   0x7
CTRL_BAR     =   0x8
CTRL_BA      =   0x9
CTRL_PS_POLL =   0xA
CTRL_RTS     =   0xB
CTRL_CTS     =   0xC
CTRL_ACK     =   0xD
CTRL_CF_END  =   0xE
CTRL_END_ACK =   0xF

ST_ASSOC_REQUEST      =  0x0
ST_ASSOC_RESPONSE     =  0x1
ST_REASSOC_REQUEST    =  0x2
ST_REASSOC_RESPONSE   =  0x3
ST_PROBE_REQUEST      =  0x4
ST_PROBE_RESPONSE     =  0x5
ST_BEACON             =  0x8
ST_ATIM               =  0x9
ST_DISASSOC           =  0xA
ST_AUTH               =  0xB
ST_DEAUTH             =  0xC
ST_ACTION             =  0xD 

DATA_DATA                   =    0x0
DATA_DATA_CF_ACK            =    0x1
DATA_DATA_CF_POLL           =    0x2
DATA_DATA_CF_ACK_POLL       =    0x3
DATA_NODATA                 =    0x4
DATA_NODATA_CF_ACK          =    0x5
DATA_NODATA_CF_POLL         =    0x6
DATA_NODATA_CF_ACK_POLL     =	 0x7

DATA_QOS_DATA               =    0x8
DATA_QOS_DATA_CF_ACK        =    0x9
DATA_QOS_DATA_CF_POLL       =    0xA
DATA_QOS_DATA_CF_ACK_POLL   =    0xB
DATA_QOS_NODATA             =    0xC
DATA_QOS_CF_POLL_NODATA     =    0xE
DATA_QOS_CF_ACK_POLL_NODATA =    0xF

IEEE80211_TX_RC_USE_SHORT_PREAMBLE  = 1<< 2
IEEE80211_TX_RC_40_MHZ_WIDTH        = 1<< 5
IEEE80211_TX_RC_SHORT_GI            = 1<< 7

MGMT_BEACON_STRUCT_SIZE= 78
MGMT_COMMON_STRUCT_SIZE= 74
MGMT_ERR_STRUCT_SIZE= 74
CTRL_STRUCT_SIZE= 70
CTRL_ERR_STRUCT_SIZE=70
DATA_STRUCT_SIZE= 78
DATA_ERR_STRUCT_SIZE=78
RADIOTAP_RX_LEN=58
RADIOTAP_TX_LEN=48
FCS_LEN=4


class radiotap_rx :
	IEEE80211_RADIOTAP_TSFT=0
	IEEE80211_RADIOTAP_FLAGS=1
	IEEE80211_RADIOTAP_RATE=2
	IEEE80211_RADIOTAP_CHANNEL=3
	IEEE80211_RADIOTAP_FHSS=4
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL=5
	IEEE80211_RADIOTAP_DBM_ANTNOISE=6
  	IEEE80211_RADIOTAP_LOCK_QUALITY = 7
  	IEEE80211_RADIOTAP_TX_ATTENUATION = 8
  	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10
  	IEEE80211_RADIOTAP_ANTENNA = 11
  	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12
  	IEEE80211_RADIOTAP_DB_ANTNOISE = 13
  	IEEE80211_RADIOTAP_RX_FLAGS = 14
  	IEEE80211_RADIOTAP_TX_FLAGS = 15
  	IEEE80211_RADIOTAP_RTS_RETRIES = 16
  	IEEE80211_RADIOTAP_DATA_RETRIES = 17
	IEEE80211_RADIOTAP_MCS = 19

	IEEE80211_RADIOTAP_PHYERR_COUNT = 20
	IEEE80211_RADIOTAP_CCK_PHYERR_COUNT = 21
	IEEE80211_RADIOTAP_OFDM_PHYERR_COUNT = 22
	IEEE80211_RADIOTAP_TOTAL_TIME=23
	IEEE80211_RADIOTAP_QUEUE_SIZES=24
	IEEE80211_RADIOTAP_COLLECTION=25	
	IEEE80211_RADIOTAP_CAPLEN = 26
	IEEE80211_RADIOTAP_RSSI = 27
	IEEE80211_RADIOTAP_RATES_TRIED=28
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30
	IEEE80211_RADIOTAP_EXT = 31

class channel_flag :
	IEEE80211_CHAN_TURBO = 0x0010  #Turbo channel 
	IEEE80211_CHAN_CCK  =0x0020  #CCK channel 
	IEEE80211_CHAN_OFDM =0x0040  # OFDM channel 
	IEEE80211_CHAN_2GHZ =0x0080  #2 GHz spectrum channel.
	IEEE80211_CHAN_5GHZ =0x0100  # 5 GHz spectrum channel 
	IEEE80211_CHAN_PASSIVE = 0x0200  # Only passive scan allowed 
	IEEE80211_CHAN_DYN = 0x0400  # Dynamic CCK-OFDM channel 
	IEEE80211_CHAN_GFSK= 0x0800  # GFSK channel (FHSS PHY) 


class mcs_flags :
	IEEE80211_RADIOTAP_MCS_HAVE_BW  =  0x01
	IEEE80211_RADIOTAP_MCS_HAVE_MCS =  0x02
	IEEE80211_RADIOTAP_MCS_HAVE_GI =  0x04
	IEEE80211_RADIOTAP_MCS_BW_MASK = 0x03
	IEEE80211_RADIOTAP_MCS_BW_40  =  1
	IEEE80211_RADIOTAP_MCS_SGI   = 0x04
	MAX_MCS_INDEX = 76

class flag:
	 IEEE80211_RADIOTAP_F_FCS = 0x10  # frame includes FCS 
	 IEEE80211_RADIOTAP_F_HOMESAW_FAILED_PHY= 0x20 #frame has PHY ERR
	 IEEE80211_RADIOTAP_F_HOMESAW_RX_AGG =0x10 #frame has PHY ERR
	 IEEE80211_RADIOTAP_F_TX_CTS= 0x0002  # used cts 'protection' 
	 IEEE80211_RADIOTAP_F_TX_RTS= 0x0004  #used rts/cts handshake 
	 IEEE80211_RADIOTAP_F_TX_NOACK= 0x0008  #don't expect an ack 
	 IEEE80211_RADIOTAP_F_TX_AGG= 0x0040  # don't expect an ack 
	 IEEE80211_RADIOTAP_F_BADFCS= 0x40  # bad FCS 
	 IEEE80211_RADIOTAP_F_RX_BADPLCP = 0x0002 #bad plcp in rx_flags 
	 IEEE80211_RADIOTAP_F_SHORTPRE =  0x02  
	 IEEE80211_RADIOTAP_F_CFP      =  0x01  
	 IEEE80211_RADIOTAP_F_WEP      =  0x04  
	 IEEE80211_RADIOTAP_F_FRAG     =  0x08  
	 IEEE80211_RADIOTAP_F_TX_FAIL  =  0x0001


IEEE80211_CHAN_TURBO   = 0x00010 # Turbo channel */
IEEE80211_CHAN_CCK     = 0x00020 # CCK channel */
IEEE80211_CHAN_OFDM    = 0x00040 # OFDM channel */
IEEE80211_CHAN_2GHZ    = 0x00080 # 2 GHz spectrum channel. */
IEEE80211_CHAN_5GHZ    = 0x00100 # 5 GHz spectrum channel */
IEEE80211_CHAN_PASSIVE = 0x00200 # Only passive scan allowed */
IEEE80211_CHAN_DYN     = 0x00400 # Dynamic CCK-OFDM channel */
IEEE80211_CHAN_GFSK    = 0x00800 # GFSK channel (FHSS PHY) */
IEEE80211_CHAN_GSM     = 0x01000 # 900 MHz spectrum channel */
IEEE80211_CHAN_STURBO  = 0x02000 # 11a static turbo channel only */
IEEE80211_CHAN_HALF    = 0x04000 # Half rate channel */
IEEE80211_CHAN_QUARTER = 0x08000 # Quarter rate channel */
IEEE80211_CHAN_HT20    = 0x10000 # HT 20 channel */
IEEE80211_CHAN_HT40U   = 0x20000 # HT 40 channel w/ ext above */
IEEE80211_CHAN_HT40D   = 0x40000 # HT 40 channel w/ ext below */



IEEE80211_CHAN_FHSS = (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
IEEE80211_CHAN_A =   (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
IEEE80211_CHAN_B =    (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
IEEE80211_CHAN_PUREG = (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
IEEE80211_CHAN_G =   (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

def IS_CHAN_FHSS(flags) :
        return ((flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
def IS_CHAN_A(flags) :
        return ((flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
def IS_CHAN_B(flags) :
        return ((flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
def IS_CHAN_PUREG(flags) :
        return ((flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
def IS_CHAN_G(flags) :
        return ((flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
def IS_CHAN_ANYG(flags) :
        return (IS_CHAN_PUREG(flags) or IS_CHAN_G(flags))
        
def seqctl_frag_number(x) : 
	return (x) & 0x00f		

def seqctl_seq_number(x):
	return 	(((x) & 0xfff0) >> 4 )



ht_rates = [

  [       [    6.5,    7.2, ],
     [   13.5,     15.0, ],
  ],

  
  [       [   13.0,           14.4, ],
     [   27.0,           30.0, ],
  ],

  
  [       [   19.5,           21.7, ],
     [   40.5,           45.0, ],
  ],

  
  [       [   26.0,           28.9, ],
     [   54.0,           60.0, ],
  ],

  [       [   39.0,           43.3, ],
     [   81.0,           90.0, ],
  ],


  [       [   52.0,           57.8, ],
     [  108.0,          120.0, ],
  ],


  [       [   58.5,           65.0, ],
     [  121.5,          135.0, ],
  ],


  [       [   65.0,           72.2, ],
     [   135.0,         150.0, ],
  ],


  [       [   13.0,           14.4, ],
     [   27.0,           30.0, ],
  ],


  [       [   26.0,           28.9, ],
     [   54.0,           60.0, ],
  ],


  [       [   39.0,           43.3, ],
     [   81.0,           90.0, ],
  ],


  [       [   52.0,           57.8, ],
     [  108.0,          120.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [  104.0,          115.6, ],
     [  216.0,          240.0, ],
  ],


  [       [  117.0,          130.0, ],
     [  243.0,          270.0, ],
  ],


  [       [  130.0,          144.4, ],
     [  270.0,          300.0, ],
  ],


  [       [   19.5,           21.7, ],
     [   40.5,           45.0, ],
  ],


  [       [   39.0,           43.3, ],
     [   81.0,           90.0, ],
  ],


  [       [   58.5,           65.0, ],
     [  121.5,          135.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [  117.0,          130.0, ],
     [  243.0,          270.0, ],
  ],


  [       [  156.0,          173.3, ],
     [  324.0,          360.0, ],
  ],


  [       [  175.5,          195.0, ],
     [  364.5,          405.0, ],
  ],


  [       [  195.0,          216.7, ],
     [  405.0,          450.0, ],
  ],


  [       [   26.0,           28.9, ],
     [   54.0,           60.0, ],
  ],


  [       [   52.0,           57.8, ],
     [  108.0,          120.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [  104.0,          115.6, ],
     [  216.0,          240.0, ],
  ],


  [       [  156.0,          173.3, ],
     [  324.0,          360.0, ],
  ],


  [       [  208.0,          231.1, ],
     [  432.0,          480.0, ],
  ],


  [       [  234.0,          260.0, ],
     [  486.0,          540.0, ],
  ],


  [       [  260.0,          288.9, ],
     [  540.0,          600.0, ],
  ],


  [       [    0.0,            0.0, ], 
     [    6.0,            6.7, ],
  ],


  [       [   39.0,           43.3, ],
     [   81.0,           90.0, ],
  ],

  [       [   52.0,           57.8, ],
     [  108.0,          120.0, ],
  ],


  [       [   65.0,           72.2, ],
     [  135.0,          150.0, ],
  ],


  [       [   58.5,           65.0, ],
     [  121.5,          135.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [   97.5,          108.3, ],
     [  202.5,          225.0, ],
  ],


  [       [   52.0,           57.8, ],
     [  108.0,          120.0, ],
  ],


  [       [   65.0,           72.2, ],
     [  135.0,          150.0, ],
  ],


  [       [   65.0,           72.2, ],
     [  135.0,          150.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [   91.0,          101.1, ],
     [  189.0,          210.0, ],
  ],


  [       [   91.0,          101.1, ],
     [  189.0,          210.0, ],
  ],


  [       [  104.0,          115.6, ],
     [  216.0,          240.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [   97.5,          108.3, ],
     [  202.5,          225.0, ],
  ],


  [       [   97.5,          108.3, ],
     [  202.5,          225.0, ],
  ],


  [       [  117.0,          130.0, ],
     [  243.0,          270.0, ],
  ],


  [       [  136.5,          151.7, ],
     [  283.5,          315.0, ],
  ],


  [       [  136.5,          151.7, ],
     [  283.5,          315.0, ],
  ],


  [       [  156.0,          173.3, ],
     [  324.0,          360.0, ],
  ],


  [       [   65.0,           72.2, ],
     [  135.0,          150.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [   91.0,          101.1, ],
     [  189.0,          210.0, ],
  ],


  [       [   78.0,           86.7, ],
     [  162.0,          180.0, ],
  ],


  [       [   91.0,          101.1, ],
     [  189.0,          210.0, ],
  ],


  [       [  104.0,          115.6, ],
     [  216.0,          240.0, ],
  ],


  [       [  117.0,          130.0, ],
     [  243.0,          270.0, ],
  ],


  [       [  104.0,          115.6, ],
     [  216.0,          240.0, ],
  ],


  [       [  117.0,          130.0, ],
     [  243.0,          270.0, ],
  ],


  [       [  130.0,          144.4, ],
     [  270.0,          300.0, ],
  ],


  [       [  130.0,          144.4, ],
     [  270.0,          300.0, ],
  ],


  [       [  143.0,          158.9, ],
     [  297.0,          330.0, ],
  ],


  [       [   97.5,          108.3, ],
     [  202.5,          225.0, ],
  ],


  [       [  117.0,          130.0, ],
     [  243.0,          270.0, ],
  ],


  [       [  136.5,          151.7, ],
     [  283.5,          315.0, ],
  ],


  [       [  117.0,          130.0, ],
     [  243.0,          270.0, ],
  ],


  [       [  136.5,          151.7, ],
     [  283.5,          315.0, ],
  ],


  [       [  156.0,          173.3, ],
     [  324.0,          360.0, ],
  ],


  [       [  175.5,          195.0, ],
     [  364.5,          405.0, ],
  ],


  [       [  156.0,          173.3, ],
     [  324.0,          360.0, ],
  ],


  [       [  175.5,          195.0, ],
     [  364.5,          405.0, ],
  ],


  [       [  195.0,          216.7, ],
     [  405.0,          450.0, ],
  ],


  [       [  195.0,          216.7, ],
     [  405.0,          450.0, ],
  ],


  [       [  214.5,          238.3, ],
     [  445.5,          495.0, ],
  ],
]
