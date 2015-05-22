/*
 * Wash - Main and usage functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "wpsmon.h"

int main(int argc, char *argv[])
{
	int c = 0;
	FILE *fp = NULL;
	int long_opt_index = 0, i = 0, channel = 0, passive = 0, mode = 0;
	int source = INTERFACE, ret_val = EXIT_FAILURE;
	struct bpf_program bpf = { 0 };
	char *out_file = NULL, *last_optarg = NULL, *target = NULL, *bssid = NULL;
	char *short_options = "i:c:n:o:b:5sfuCDh";
        struct option long_options[] = {
		{ "bssid", required_argument, NULL, 'b' },
                { "interface", required_argument, NULL, 'i' },
                { "channel", required_argument, NULL, 'c' },
		{ "out-file", required_argument, NULL, 'o' },
		{ "probes", required_argument, NULL, 'n' },
		{ "daemonize", no_argument, NULL, 'D' },
		{ "file", no_argument, NULL, 'f' },
		{ "ignore-fcs", no_argument, NULL, 'C' },
		{ "5ghz", no_argument, NULL, '5' },
		{ "scan", no_argument, NULL, 's' },
		{ "survey", no_argument, NULL, 'u' },
                { "help", no_argument, NULL, 'h' },
                { 0, 0, 0, 0 }
        };

	fprintf(stderr, "\nWash v%s WiFi Protected Setup Scan Tool\n", PACKAGE_VERSION);
        fprintf(stderr, "Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>\n\n");

	globule_init();
	sql_init();
	create_ap_table();
	set_auto_channel_select(0);
	set_wifi_band(BG_BAND);
	set_debug(INFO);
	set_validate_fcs(1);
	set_log_file(stdout);
	set_max_num_probes(DEFAULT_MAX_NUM_PROBES);

	while((c = getopt_long(argc, argv, short_options, long_options, &long_opt_index)) != -1)
        {
                switch(c)
                {
			case 'f':
				source = PCAP_FILE;
				break;
			case 'i':
				set_iface(optarg);
				break;
			case 'b':
				bssid = strdup(optarg);
				break;
			case 'c':
				channel = atoi(optarg);
				set_fixed_channel(1);
				break;
			case '5':
				set_wifi_band(AN_BAND);
				break;
			case 'n':
				set_max_num_probes(atoi(optarg));
				break;
			case 'o':
				out_file = strdup(optarg);
				break;
			case 's':
				mode = SCAN;
				break;
			case 'u':
				mode = SURVEY;
				break;
			case 'C':
				set_validate_fcs(0);
				break;
			case 'D':
				daemonize();
				break;
			default:
				usage(argv[0]);
				goto end;
		}

		/* Track the last optarg. This is used later when looping back through any specified pcap files. */
		if(optarg)
		{
			if(last_optarg)
			{
				free(last_optarg);
			}

			last_optarg = strdup(optarg);
		}
	}

	/* The interface value won't be set if capture files were specified; else, there should have been an interface specified */
	if(!get_iface() && source != PCAP_FILE)
	{
		usage(argv[0]);
		goto end;
	}

	if(get_iface() && source == PCAP_FILE)
	{
		cprintf(CRITICAL, "[X] ERROR: -i and -f options cannot be used together.\n");
		usage(argv[0]);
		goto end;
	}

	/* If we're reading from a file, be sure we don't try to transmit probe requests */
	if(source == PCAP_FILE)
	{
		passive = 1;
	}

	/* Open the output file, if any. If none, write to stdout. */
	if(out_file)
	{
		fp = fopen(out_file, "wb");
		if(!fp)
		{
			cprintf(CRITICAL, "[X] ERROR: Failed to open '%s' for writing\n", out_file);
			goto end;
		}

		set_log_file(fp);
	}

	/* 
	 * Loop through all of the specified capture sources. If an interface was specified, this will only loop once and the
	 * call to monitor() will block indefinitely. If capture files were specified, this will loop through each file specified
	 * on the command line and monitor() will return after each file has been processed.
	 */
	for(i=argc-1; i>0; i--)
	{
		/* If the source is a pcap file, get the file name from the command line */
		if(source == PCAP_FILE)
		{
			/* If we've gotten to the arguments, we're done */
			if((argv[i][0] == '-') ||
			   (last_optarg && (memcmp(argv[i], last_optarg, strlen(last_optarg)) == 0))
			)
			{
				break;
			}
			else
			{
				target = argv[i];
			}
		}
		/* Else, use the specified interface name */
		else
		{
			target = get_iface();
		}

		set_handle(capture_init(target));
		if(!get_handle())
		{
			cprintf(CRITICAL, "[X] ERROR: Failed to open '%s' for capturing\n", get_iface());
			goto end;
		}

		if(pcap_compile(get_handle(), &bpf, PACKET_FILTER, 0, 0) != 0)
		{
			cprintf(CRITICAL, "[X] ERROR: Failed to compile packet filter\n");
			goto end;
		}
		
		if(pcap_setfilter(get_handle(), &bpf) != 0)
		{
			cprintf(CRITICAL, "[X] ERROR: Failed to set packet filter\n");
			goto end;
		}

		/* Do it. */
		monitor(bssid, passive, source, channel, mode);
		printf("\n");
	}

	ret_val = EXIT_SUCCESS;

end:
	globule_deinit();
	sql_cleanup();
	if(bssid) free(bssid);
	if(out_file) free(out_file);
	if(wpsmon.fp) fclose(wpsmon.fp);
	return ret_val;
}

/* Monitors an interface (or capture file) for WPS data in beacon packets or probe responses */
void monitor(char *bssid, int passive, int source, int channel, int mode)
{
	struct sigaction act;
	struct itimerval timer;
	struct pcap_pkthdr header;
	static int header_printed;
        const u_char *packet = NULL;

        memset(&act, 0, sizeof(struct sigaction));
        memset(&timer, 0, sizeof(struct itimerval));

	/* If we aren't reading from a pcap file, set the interface channel */
	if(source == INTERFACE)
	{
		/* 
		 * If a channel has been specified, set the interface to that channel. 
		 * Else, set a recurring 1 second timer that will call sigalrm() and switch to 
		 * a new channel.
		 */
		if(channel > 0)
		{
			change_channel(channel);
		}
		else
		{
        		act.sa_handler = sigalrm_handler;
        		sigaction (SIGALRM, &act, 0);
			ualarm(CHANNEL_INTERVAL, CHANNEL_INTERVAL);
			change_channel(1);
		}
	}

	if(!header_printed)
	{
		cprintf(INFO, "BSSID                  Channel       RSSI       WPS Version       WPS Locked        ESSID\n");
		cprintf(INFO, "---------------------------------------------------------------------------------------------------------------\n");
		header_printed = 1;
	}

	while((packet = next_packet(&header)))
	{
		parse_wps_settings(packet, &header, bssid, passive, mode, source);
		memset((void *) packet, 0, header.len);
	}

	return;
}

void parse_wps_settings(const u_char *packet, struct pcap_pkthdr *header, char *target, int passive, int mode, int source)
{
	struct radio_tap_header *rt_header = NULL;
	struct dot11_frame_header *frame_header = NULL;
	struct libwps_data *wps = NULL;
	enum encryption_type encryption = NONE;
	char *bssid = NULL, *ssid = NULL, *lock_display = NULL;
	int wps_parsed = 0, probe_sent = 0, channel = 0, rssi = 0;
	static int channel_changed = 0;

	wps = malloc(sizeof(struct libwps_data));
	memset(wps, 0, sizeof(struct libwps_data));

	if(packet == NULL || header == NULL || header->len < MIN_BEACON_SIZE)
        {
                goto end;
        }

	rt_header = (struct radio_tap_header *) radio_header(packet, header->len);
	frame_header = (struct dot11_frame_header *) (packet + rt_header->len);

	/* If a specific BSSID was specified, only parse packets from that BSSID */
	if(!is_target(frame_header))
	{
		goto end;
	}

	set_ssid(NULL);
	bssid = (char *) mac2str(frame_header->addr3, ':');

	if(bssid)
	{
		if((target == NULL) ||
		   (target != NULL && strcmp(bssid, target) == 0))
		{
			channel = parse_beacon_tags(packet, header->len);
			rssi = signal_strength(packet, header->len);
			ssid = (char *) get_ssid();

			if(target != NULL && channel_changed == 0)
			{
				ualarm(0, 0);
				change_channel(channel);
				channel_changed = 1;
			}

			if(frame_header->fc.sub_type == PROBE_RESPONSE ||
                                   frame_header->fc.sub_type == SUBTYPE_BEACON)
			{
				wps_parsed = parse_wps_parameters(packet, header->len, wps);
			}
	
			if(!is_done(bssid) && (get_channel() == channel || source == PCAP_FILE))
			{
				if(frame_header->fc.sub_type == SUBTYPE_BEACON && 
				   mode == SCAN && 
				   !passive && 
				   should_probe(bssid))
				{
					send_probe_request(get_bssid(), get_ssid());
					probe_sent = 1;
				}
		
				if(!insert(bssid, ssid, wps, encryption, rssi))
				{
					update(bssid, ssid, wps, encryption);
				}
				else if(wps->version > 0)
				{
					switch(wps->locked)
					{
						case WPSLOCKED:
							lock_display = YES;
							break;
						case UNLOCKED:
						case UNSPECIFIED:
							lock_display = NO;
							break;
					}

					cprintf(INFO, "%17s      %2d            %.2d        %d.%d               %s               %s\n", bssid, channel, rssi, (wps->version >> 4), (wps->version & 0x0F), lock_display, ssid);
				}

				if(probe_sent)
				{
					update_probe_count(bssid);
				}

				/* 
				 * If there was no WPS information, then the AP does not support WPS and we should ignore it from here on.
				 * If this was a probe response, then we've gotten all WPS info we can get from this AP and should ignore it from here on.
				 */
				if(!wps_parsed || frame_header->fc.sub_type == PROBE_RESPONSE)
				{
					mark_ap_complete(bssid);
				}
	
			}
		}

		/* Only update received signal strength if we are on the same channel as the AP, otherwise power measurements are screwy */
		if(channel == get_channel())
		{
			update_ap_power(bssid, rssi);
		}

		free(bssid);
		bssid = NULL;
	}

end:
	if(wps) free(wps);

	return;
}

/* Does what it says */
void send_probe_request(unsigned char *bssid, char *essid)
{
	const void *probe = NULL;
	size_t probe_size = 0;

	probe = build_wps_probe_request(bssid, essid, &probe_size);
	if(probe)
	{
		pcap_inject(get_handle(), probe, probe_size);
		free((void *) probe);
	}

	return;
}

/* Whenever a SIGALRM is thrown, go to the next 802.11 channel */
void sigalrm_handler(int x)
{
	next_channel();
}

void usage(char *prog)
{
	fprintf(stderr, "Required Arguments:\n");
	fprintf(stderr, "\t-i, --interface=<iface>              Interface to capture packets on\n");
	fprintf(stderr, "\t-f, --file [FILE1 FILE2 FILE3 ...]   Read packets from capture files\n");

	fprintf(stderr, "\nOptional Arguments:\n");
	fprintf(stderr, "\t-c, --channel=<num>                  Channel to listen on [auto]\n");
	fprintf(stderr, "\t-o, --out-file=<file>                Write data to file\n");
	fprintf(stderr, "\t-n, --probes=<num>                   Maximum number of probes to send to each AP in scan mode [%d]\n", DEFAULT_MAX_NUM_PROBES);
	fprintf(stderr, "\t-D, --daemonize                      Daemonize wash\n");
	fprintf(stderr, "\t-C, --ignore-fcs                     Ignore frame checksum errors\n");
	fprintf(stderr, "\t-5, --5ghz                           Use 5GHz 802.11 channels\n");
	fprintf(stderr, "\t-s, --scan                           Use scan mode\n");
	fprintf(stderr, "\t-u, --survey                         Use survey mode [default]\n");
	fprintf(stderr, "\t-h, --help                           Show help\n");
	
	fprintf(stderr, "\nExample:\n");
	fprintf(stderr, "\t%s -i mon0\n\n", prog);

	return;
}
