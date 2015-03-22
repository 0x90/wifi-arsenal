# Author : Abhinav Narain
# Date : 23 April 2013 
#purpose : part of library regarding the rate information
# File belongs to part of Data Parsing Library
#static u32 ath_pkt_duration(struct ath_softc *sc, u8 rix, int pktlen,
def ath_pkt_duration(rix, pktlen, width, half_gi,shortPreamble):
    def HT_RC_2_STREAMS(_rc):
        return ((((_rc) & 0x78) >> 3) + 1)    
    def HT_LTF(_ns):
        return (4 * (_ns))
    def SYMBOL_TIME(_ns):
        return ((_ns) << 2) # ns 4 us 
    def SYMBOL_TIME_HALFGI(_ns):
        return (((_ns) * 18 + 4) / 5)  # ns 3.6 us 
    def NUM_SYMBOLS_PER_USEC(_usec):
        return (_usec >> 2)
    def NUM_SYMBOLS_PER_USEC_HALFGI(_usec): 
        return (((_usec*5)-4)/18)



    bits_per_symbol = [    
    [    26,   54 ],     
    [    52,  108 ],     
    [    78,  162 ],     
    [   104,  216 ],     
    [   156,  324 ],     
    [   208,  432 ],     
    [   234,  486 ],    
    [   260,  540 ],      ]

    
    nbits, nsymbits, duration, nsymbols, streams=0,0,0,0,0

    BITS_PER_BYTE  = 8
    OFDM_PLCP_BITS = 22
    L_STF          = 8
    L_LTF          = 8
    L_SIG          = 4
    HT_SIG         = 8
    HT_STF         = 4
    streams = HT_RC_2_STREAMS(rix)
    nbits = (pktlen << 3) + OFDM_PLCP_BITS
    nsymbits = bits_per_symbol[rix % 8][width] * streams
    nsymbols = (nbits + nsymbits - 1) / nsymbits

    if not(half_gi) :
        duration = SYMBOL_TIME(nsymbols)
    else:
        duration = SYMBOL_TIME_HALFGI(nsymbols)

    duration += L_STF + L_LTF + L_SIG + HT_SIG + HT_STF + HT_LTF(streams)

    return duration

#phy, int kbps, u32 frameLen, u16 rateix,shortPreamble)
def ath9k_hw_computetxtime(phy,kbps,frameLen,rateix,shortPreamble,curchan):
    bitsPerSymbol, numBits, numSymbols, phyTime, txTime=0,0,0,0,0
    WLAN_RC_PHY_OFDM=0
    WLAN_RC_PHY_CCK=1
    WLAN_RC_PHY_HT_20_SS=2
    WLAN_RC_PHY_HT_20_DS=3
    WLAN_RC_PHY_HT_20_TS=4
    WLAN_RC_PHY_HT_40_SS=5
    WLAN_RC_PHY_HT_40_DS=6
    WLAN_RC_PHY_HT_40_TS=7
    WLAN_RC_PHY_HT_20_SS_HGI=8
    WLAN_RC_PHY_HT_20_DS_HGI=9
    WLAN_RC_PHY_HT_20_TS_HGI=10
    WLAN_RC_PHY_HT_40_SS_HGI=11
    WLAN_RC_PHY_HT_40_DS_HGI=12
    WLAN_RC_PHY_HT_40_TS_HGI=13
    WLAN_RC_PHY_MAX=14
    CCK_SIFS_TIME      =  10
    CCK_PREAMBLE_BITS  = 144
    CCK_PLCP_BITS      =  48

    OFDM_SIFS_TIME      =  16
    OFDM_PREAMBLE_TIME  =  20
    OFDM_PLCP_BITS      =  22
    OFDM_SYMBOL_TIME    =  4

    OFDM_SIFS_TIME_HALF     = 32
    OFDM_PREAMBLE_TIME_HALF = 40
    OFDM_PLCP_BITS_HALF     = 22
    OFDM_SYMBOL_TIME_HALF   = 8

    OFDM_SIFS_TIME_QUARTER     = 64
    OFDM_PREAMBLE_TIME_QUARTER = 80
    OFDM_PLCP_BITS_QUARTER     = 22
    OFDM_SYMBOL_TIME_QUARTER   = 16

    CHANNEL_HALF     = 0x04000
    CHANNEL_QUARTER  = 0x08000

    def IS_CHAN_HALF_RATE(_c) :
        return (not(_c & CHANNEL_HALF) == 0)
    def IS_CHAN_QUARTER_RATE(_c) :
        return (not (_c & CHANNEL_QUARTER) == 0)

    def DIV_ROUND_UP(n, d):
        return (((n) + (d) - 1) / (d))
    
    if (kbps == 0):
        return 0
    #print phy, WLAN_RC_PHY_CCK, WLAN_RC_PHY_OFDM
    if phy == WLAN_RC_PHY_CCK:
        phyTime = CCK_PREAMBLE_BITS + CCK_PLCP_BITS
        if shortPreamble:
            phyTime >>= 1
        numBits = frameLen << 3
        txTime = CCK_SIFS_TIME + phyTime + ((numBits * 1000) / kbps)    
    elif  phy ==WLAN_RC_PHY_OFDM:
        if (curchan and IS_CHAN_QUARTER_RATE(curchan)) :
            bitsPerSymbol = (kbps * OFDM_SYMBOL_TIME_QUARTER) / 1000
            numBits = OFDM_PLCP_BITS + (frameLen << 3)
            numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol)
            txTime = OFDM_SIFS_TIME_QUARTER+OFDM_PREAMBLE_TIME_QUARTER+(numSymbols * OFDM_SYMBOL_TIME_QUARTER)
        elif (curchan and IS_CHAN_HALF_RATE(curchan)) :
            bitsPerSymbol = (kbps * OFDM_SYMBOL_TIME_HALF) / 1000;
            numBits = OFDM_PLCP_BITS + (frameLen << 3)
            numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol);
            txTime = OFDM_SIFS_TIME_HALF + OFDM_PREAMBLE_TIME_HALF + (numSymbols * OFDM_SYMBOL_TIME_HALF)
        else :
            bitsPerSymbol = (kbps * OFDM_SYMBOL_TIME) / 1000
            numBits = OFDM_PLCP_BITS + (frameLen << 3)
            numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol)
            txTime = OFDM_SIFS_TIME + OFDM_PREAMBLE_TIME + (numSymbols * OFDM_SYMBOL_TIME)            
            #check the default case and change txTime accordingly
    return txTime;

