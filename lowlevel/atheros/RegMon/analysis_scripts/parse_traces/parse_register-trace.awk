#!/opt/local/bin/gawk --non-decimal-data -f
#
# Thomas Huehn 2012

BEGIN{
    #print header
    print "timestamp mac_counter_diff tx_counter_diff rx_counter_diff ed_counter_diff noise rssi nav tsf_high tsf_low kernel_time_diff expected_mac_count_kernel tsf_time_diff expected_mac_count_tsf ";
}
{
#
if (NR == 1) {
    time	= $1 * 1000000;
    mac		= $2;
    tx		= $3;
    rx		= $4;
    ed		= $5;
    noise_raw	= $6;
    tsf_high	= $9;
    tsf_low	= $10;
    noise	= -1 - xor(rshift(noise_raw, 19), 0x1ff);
    pot_reset	= 0;
}
else {
    #time_diff
    k_time_diff  = $1 * 1000000 - time;

    #mac_diff
    if ($2 >= mac) {
	    mac_diff	 = $2 - mac;
	    tx_diff	 = $3 - tx;
	    rx_diff	 = $4 - rx;
	    ed_diff	 = $5 - ed;
    }
    else {
	    pot_reset	  = 1;
	    mac_diff	  = strtonum($2);
	    tx_diff	  = strtonum($3);
	    rx_diff	  = strtonum($4);
	    ed_diff	  = strtonum($5);
    }

    #noise calculation
    if (noise_raw != $6) {
	noise = -1 - xor(rshift(noise_raw, 19), 0x1ff);
	noise_raw = $6;
    }

#rssi calculation
    rssi  = strtonum($7);

#nav
    nav   = strtonum($8);

#tsf
    if ($9 > tsf_high)
	tsf_time_diff = (lshift($9, 32) + $10) - (lshift(tsf_high, 32) + tsf_low);

    else if ($9 == tsf_high && $10 > tsf_low)
	tsf_time_diff = $10 - tsf_low;

    else
	tsf_time_diff = 0;

#expected mac count
    k_exp_mac	= k_time_diff * 44;
    tsf_exp_mac = tsf_time_diff * 44;

#final print
    print $1, mac_diff, tx_diff, rx_diff, ed_diff, noise, rssi, nav, k_time_diff, k_exp_mac, tsf_time_diff, tsf_exp_mac, pot_reset

#refresh lines
    time	= $1 * 1000000;
    mac		= $2;
    tx		= $3;
    rx		= $4;
    ed		= $5;
    tsf_high	= $9;
    tsf_low	= $10;
    pot_reset	= 0;
}

}
END{

}
