# Hugh O'Brien 2014, obrien.hugh@gmail.com
import sys, math, csv

reader = csv.reader(sys.stdin)

#indices of input
idx_frame_num = 0
idx_header_len = 1
idx_mac_timestamp = 2
idx_preamble = 3
idx_datarate = 4
idx_length = 5
idx_rssi = 6

#valid rates
rates_ofdm = ['6', '9', '12', '18', '24', '36', '48', '54']
rates_cck = ['5.5', '11'] #these could be ints if it weren't for 5.5
rates_dsss = ['1', '2']

mod_ofdm = "ofdm"
mod_cck = "cck"
mod_dsss = "dsss"
pre_ofdm = "ofdm"
pre_long = "long"
pre_short = "short"

#units are microseconds
dsss_preamble_long = 144
dsss_header_long = 48
dsss_preamble_short = 72
dsss_header_short = int(dsss_header_long / 2 )#sent at 2mbs, ensure integer
ofdm_preamble = 16 #802.11-2007 p.600
ofdm_signal = 4

radiotap_header_len = 26 #at least it is from ath9k

#these are only valid betwixt two good lines
last_mac_timestamp = 0
last_mpdu_duration = 0

#initialise counters
bad_header_len = 0 #short radiotap headers appear sometimes, driver issue methinks
bad_time_calc = 0 #calculation can be negative, which is invalid, bad timers perhaps? Serious issue.
csv_header_printed = False

for line in reader:

    frame_num = int(line[idx_frame_num]) #kept for debugging

    if int(line[idx_header_len]) != radiotap_header_len:
        bad_header_len += 1
        last_mac_timestamp = 0 #discard data
        last_mpdu_duration = 0
        continue

    rssi = int(line[idx_rssi])

    #experiment1
    #if rssi < -56: #presume these aren't an issue. For cap2, this is 35% of frames
        #continue

    datarate = line[idx_datarate] #compare as a string, thankfully no overlapping rates
    if datarate in rates_ofdm:
        modulation = mod_ofdm
    elif datarate in rates_cck:
        modulation = mod_cck
    elif datarate in rates_dsss:
        modulation = mod_dsss

    #experiment2
    #if modulation == mod_ofdm: #what if ofdm didn't cause interference?
        #continue

    preamble_flag = int(line[idx_preamble])
    if modulation == mod_ofdm: #preamble not valid for ofdm
        preamble = pre_ofdm
    elif preamble_flag == 0:
        preamble = pre_long
    elif preamble_flag == 1:
        preamble = pre_short

    if preamble == pre_ofdm:
        phy_duration = ofdm_preamble + ofdm_signal
    elif preamble == pre_long:
        phy_duration = dsss_preamble_long + dsss_header_long
    elif preamble == pre_short:
        phy_duration = dsss_preamble_short + dsss_header_short

    length = int(line[idx_length]) - radiotap_header_len
    #convert length to bits, divide by datarate to get time in micros
    mpdu_duration = int(math.ceil(length * 8 / float(datarate)))
    mac_timestamp = int(line[idx_mac_timestamp])

    if last_mac_timestamp == 0 or last_mpdu_duration == 0:
        last_mac_timestamp = mac_timestamp
        last_mpdu_duration = mpdu_duration
        continue #initial or resync frame, further calcs impossible

    #...[PHY1|MAC1]...[PHY2|MAC2]...
    #find time between the packets, given start time of MAC1 and MAC2:
    #   start of MAC2 - start of MAC1 - length of MAC1 - length of PHY2
    inactive_time = mac_timestamp - last_mac_timestamp - last_mpdu_duration - phy_duration
    #ERP signal extension would +6 last_mpdu_duration but as its actually idle time we shouldn't
    #count it as distinct from inactive_time. Therefore it's ignored. 802.11-2007 p.695

    if inactive_time < 0:
        bad_time_calc  += 1

    if not csv_header_printed:
        csv_header_printed = True
        print('inactive_time', 'modulation', 'datarate', 'phy_duration', 'mpdu_duration', 'length', 'rssi', sep=',')

    print(inactive_time, modulation, datarate, phy_duration, mpdu_duration, length, rssi, sep=',')

    last_mac_timestamp = mac_timestamp #shift values
    last_mpdu_duration = mpdu_duration;

#error summary to stderr
print("bad header:", bad_header_len, file=sys.stderr)
print("bad inactive time:", bad_time_calc, file=sys.stderr)
#do you need to resync on negative time frames? can you try and understand them better?
#run proc again with the javas slice and try to understand with wireshark
#are you so sure wlan.duration is no good?
