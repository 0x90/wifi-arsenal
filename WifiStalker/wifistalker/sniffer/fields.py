"Sniffer constants"

ELT_SSID = 0
ELT_RATES = 1
ELT_DIRECT_SPECTRUM = 3
ELT_CHANNELS = 36
ELT_QOS = 46

ELT_COUNTRY = 7
ELT_VENDOR = 221
ELT_RSN = 48 # Robust Security Network


mgmt_subtype_tag = {
    0: 'ASSOC_REQ',
    1: 'ASSOC_RESP',
    2: 'REASSOC_REQ',
    3: 'REASSOC_RESP',
    4: 'PROBE_REQ',
    5: 'PROBE_RESP',
    8: 'BEACON',
    9: 'ATM',
    10: 'DISASS',
    11: 'AUTH',
    12: 'DEAUTH',
}


ctrl_subtype_tag = {
    10: 'PS_POLL',
    11: 'RTS',
    12: 'CTS',
    13: 'ACK',
    14: 'CF_END',
    15: 'CF_ENDACK',
}

