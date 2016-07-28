/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 *				Stephan M. Guenther <moepi@moepi.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See COPYING for more details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <argp.h>
#include <endian.h>
#include <signal.h>

#include <arpa/inet.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include <moep80211/system.h>
#include <moep80211/types.h>

#include <moep80211/modules/moep80211.h>
#include <moep80211/modules/ieee8023.h>

#include "../src/util.h"

#include "../src/modules/radio/radiotap.h"


const char *argp_program_version = "ptmbeacon 1.0";
const char *argp_program_bug_address = "<leclaire@in.tum.de>";

static char args_doc[] = "IF FREQ";

static char doc[] =
"ptmbeacon - a packet transfer module for moep80211 with beacons\n\n"
"  IF                         Use the radio interface with name IF\n"
"  FREQ                       Use the frequency FREQ [in Hz] for the radio\n"
"                             interface; You can use M for MHz.";

enum fix_args {
	FIX_ARG_IF = 0,
	FIX_ARG_FREQ = 1,
	FIX_ARG_CNT
};

static struct argp_option options[] = {
	{"hwaddr", 'a', "ADDR", 0, "Set the hardware address to ADDR"},
	{"ipaddr", 'i', "ADDR", 0, "Set the ip address to ADDR"},
	{"mtu", 'm', "SIZE", 0, "Set the mtu to SIZE"},
	{}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state);

static struct argp argp = {
	options,
	parse_opt,
	args_doc,
	doc
};


struct arguments {
	char *rad;
	u8 *addr;
	struct in_addr ip;
	int mtu;
	u64 freq;
} args;


static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *args = state->input;
	char *endptr = NULL;
	long long int freq;

	switch (key) {
	case 'a':
		if (!(args->addr = ieee80211_aton(arg)))
			argp_failure(state, 1, errno, "Invalid hardware address");
		break;
	case 'i':
		if (!(inet_aton(arg, &args->ip)))
			argp_failure(state, 1, errno, "Invalid ip address");
		break;
	case 'm':
		args->mtu = strtol(arg, &endptr, 0);
		if (endptr != NULL && endptr != arg + strlen(arg))
			argp_failure(state, 1, errno, "Invalid mtu: %s", arg);
		if (args->mtu <= 0)
			argp_failure(state, 1, errno, "Invalid mtu: %d", args->mtu);
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case FIX_ARG_IF:
			args->rad = arg;
			break;
		case FIX_ARG_FREQ:
			freq = strtoll(arg, &endptr, 0);
			while (endptr != NULL && endptr != arg + strlen(arg)) {
				switch (*endptr) {
				case 'k':
				case 'K':
					freq *= 1000;
					break;
				case 'm':
				case 'M':
					freq *= 1000000;
					break;
				case 'g':
				case 'G':
					freq *= 1000000000;
					break;
				default:
					argp_failure(state, 1, errno, "Invalid frequency: %s", arg);
				}
				endptr++;
			}
			if (freq < 0)
				argp_failure(state, 1, errno, "Invalid frequency: %lld", freq);
			args->freq = freq / 1000000;
			break;
		default:
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (state->arg_num < FIX_ARG_CNT)
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}


#define MOEP_HDR_BEACON	MOEP_HDR_VENDOR_MIN


struct moep_hdr_beacon {
	struct moep_hdr_ext hdr;
} __attribute__((packed));


static moep_dev_t tap;
static moep_dev_t rad;

static sig_atomic_t run = 1;


static void sigterm(int sig)
{
	run = 0;
}

static void taph(moep_dev_t dev, moep_frame_t frame)
{
	struct moep80211_radiotap *radiotap;
	struct moep80211_hdr *hdr;
	struct moep_hdr_pctrl *pctrl;
	struct ether_header ether, *etherptr;
	size_t len;

	if (!(etherptr = moep_frame_ieee8023_hdr(frame))) {
		fprintf(stderr, "ptmbeacon: error: no ether header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	memcpy(&ether, etherptr, sizeof(ether));

	moep_dev_frame_convert(rad, frame);

	if (!(hdr = moep_frame_moep80211_hdr(frame))) {
		fprintf(stderr, "ptmbeacon: error: no moep80211 header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	hdr->frame_control = htole16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);
	memcpy(hdr->ra, ether.ether_dhost, IEEE80211_ALEN);
	memcpy(hdr->ta, ether.ether_shost, IEEE80211_ALEN);

	if (!(pctrl = (struct moep_hdr_pctrl *)moep_frame_add_moep_hdr_ext(frame,
									   MOEP_HDR_PCTRL,
									   sizeof(*pctrl)))) {
		fprintf(stderr, "ptmbeacon: error: cannot add pctrl header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	pctrl->type = htole16(be16toh(ether.ether_type));
	if (!moep_frame_get_payload(frame, &len)) {
		fprintf(stderr, "ptmbeacon: error: no payload: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	pctrl->len = htole16(len);

	if (!(radiotap = moep_frame_radiotap(frame))) {
		fprintf(stderr, "ptmbeacon: error: no radiotap header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	radiotap->rate = 2;
	radiotap->hdr.it_present = BIT(IEEE80211_RADIOTAP_RATE);
//	radiotap->mcs.mcs = 5;
//	radiotap->mcs.flags = IEEE80211_RADIOTAP_MCS_BW_20
//			   | IEEE80211_RADIOTAP_MCS_SGI;
//	radiotap->mcs.known = IEEE80211_RADIOTAP_MCS_HAVE_MCS
//			   | IEEE80211_RADIOTAP_MCS_HAVE_BW
//			   | IEEE80211_RADIOTAP_MCS_HAVE_GI;
//	radiotap->hdr.it_present = BIT(IEEE80211_RADIOTAP_MCS);

	if (moep_dev_tx(rad, frame)) {
		fprintf(stderr, "ptmbeacon: error: failed to send frame: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}

	moep_frame_destroy(frame);
}

static void radh(moep_dev_t dev, moep_frame_t frame)
{
	struct moep80211_hdr *hdr;
	struct moep_hdr_pctrl *pctrl;
	struct ether_header ether, *etherptr;

	if (!(hdr = moep_frame_moep80211_hdr(frame))) {
		fprintf(stderr, "ptmbeacon: error: no moep80211 header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}

	if (!(pctrl = (struct moep_hdr_pctrl *)moep_frame_moep_hdr_ext(frame,
								       MOEP_HDR_PCTRL))) {
		fprintf(stderr, "ptmbeacon: error: no pctrl header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}

	if (!memcmp(hdr->ta, args.addr, IEEE80211_ALEN)) {
		moep_frame_destroy(frame);
		return;
	}

	memcpy(ether.ether_dhost, hdr->ra, IEEE80211_ALEN);
	memcpy(ether.ether_shost, hdr->ta, IEEE80211_ALEN);
	ether.ether_type = htobe16(le16toh(pctrl->type));

	if (!moep_frame_adjust_payload_len(frame, le16toh(pctrl->len))) {
		fprintf(stderr, "ptmbeacon: error: failed to adjust payload len: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}

	moep_dev_frame_convert(tap, frame);

	if (!(etherptr = moep_frame_ieee8023_hdr(frame))) {
		fprintf(stderr, "ptmbeacon: error: no ether header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	memcpy(etherptr, &ether, sizeof(ether));

	if (moep_dev_tx(tap, frame)) {
		fprintf(stderr, "ptmbeacon: error: failed to send frame: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}

	moep_frame_destroy(frame);
}

static void send_beacon(void)
{
	moep_frame_t frame;
	struct moep80211_radiotap *radiotap;
	struct moep80211_hdr *hdr;
	struct moep_hdr_beacon *beacon;

	if (!(frame = moep_dev_frame_create(rad))) {
		fprintf(stderr, "ptmbeacon: cannot create frame: %s\n", strerror(errno));
		return;
	}

	if (!(hdr = moep_frame_moep80211_hdr(frame))) {
		fprintf(stderr, "ptmbeacon: error: no moep80211 header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	hdr->frame_control = htole16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);
	memset(hdr->ra, 0xff, IEEE80211_ALEN);
	memcpy(hdr->ta, args.addr, IEEE80211_ALEN);

	if (!(beacon = (struct moep_hdr_beacon *)moep_frame_add_moep_hdr_ext(frame,
									     MOEP_HDR_BEACON,
									     sizeof(*beacon)))) {
		fprintf(stderr, "ptmbeacon: error: cannot create beacon header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}

	if (!(radiotap = moep_frame_radiotap(frame))) {
		fprintf(stderr, "ptmbeacon: error: no radiotap header: %s\n", strerror(errno));
		moep_frame_destroy(frame);
		return;
	}
	radiotap->rate = 2;
	radiotap->hdr.it_present = BIT(IEEE80211_RADIOTAP_RATE);
//	radiotap->mcs.mcs = 5;
//	radiotap->mcs.flags = IEEE80211_RADIOTAP_MCS_BW_20
//			   | IEEE80211_RADIOTAP_MCS_SGI;
//	radiotap->mcs.known = IEEE80211_RADIOTAP_MCS_HAVE_MCS
//			   | IEEE80211_RADIOTAP_MCS_HAVE_BW
//			   | IEEE80211_RADIOTAP_MCS_HAVE_GI;
//	radiotap->hdr.it_present = BIT(IEEE80211_RADIOTAP_MCS);

	if (moep_dev_tx(rad, frame)) {
		fprintf(stderr, "ptmbeacon: error: failed to send frame\n");
		moep_frame_destroy(frame);
		return;
	}

	moep_frame_destroy(frame);
}

int main(int argc, char **argv)
{
	struct sigaction sact;
	sigset_t blockset, oldset;

	sact.sa_handler = sigterm;
	sigfillset(&sact.sa_mask);
	sact.sa_flags = 0;

	if (sigaction(SIGTERM, &sact, NULL)) {
		fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
		return -1;
	}
	if (sigaction(SIGINT, &sact, NULL)) {
		fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
		return -1;
	}

	memset(&args, 0, sizeof(args));
	args.mtu = 1500;
	int tx_event;
	fd_set ior;
	struct timespec interval, tmp, timeout;

	argp_parse(&argp, argc, argv, 0, 0, &args);

	if (!(tap = moep_dev_ieee8023_tap_open(args.addr, &args.ip, 24,
					       args.mtu +
					       sizeof(struct ether_header)))) {
		fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
		return -1;
	}
	if (!(rad = moep_dev_moep80211_open(args.rad, args.freq,
					    MOEP80211_CHAN_WIDTH_20_NOHT,
					    0, 0, args.mtu + radiotap_len(-1) +
					    sizeof(struct moep80211_hdr) +
					    sizeof(struct moep_hdr_pctrl)))) {
		fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
		moep_dev_close(tap);
		return -1;
	}

	if (!args.addr) {
		if (!(args.addr = malloc(IEEE80211_ALEN))) {
			fprintf(stderr, "ptmbeacon: error: failed to allocate memory\n");
			moep_dev_close(rad);
			moep_dev_close(tap);
			return -1;
		}
		if (moep_dev_tap_get_hwaddr(tap, args.addr)) {
			fprintf(stderr, "ptmbeacon: error: failed to retrieve hardware address\n");
			free(args.addr);
			moep_dev_close(rad);
			moep_dev_close(tap);
			return -1;
		}
	}

	moep_dev_set_rx_handler(tap, taph);
	moep_dev_set_rx_handler(rad, radh);
	moep_dev_pair(tap, rad);
	if ((tx_event = dup(moep_dev_get_tx_event(rad))) < 0) {
		fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
		free(args.addr);
		moep_dev_close(rad);
		moep_dev_close(tap);
		return -1;
	}

	interval.tv_sec = 1;
	interval.tv_nsec = 0;

	sigfillset(&blockset);
	if (sigprocmask(SIG_SETMASK, &blockset, &oldset)) {
		fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
		free(args.addr);
		moep_dev_close(rad);
		moep_dev_close(tap);
		return -1;
	}

	while (run) {
		FD_ZERO(&ior);
		FD_SET(tx_event, &ior);

		clock_gettime(CLOCK_REALTIME, &timeout);
		if (moep_select(tx_event + 1, &ior, NULL, NULL, NULL, &oldset) < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
				free(args.addr);
				moep_dev_close(rad);
				moep_dev_close(tap);
				return -1;
			}
		}

		if (!run)
			break;

		send_beacon();

		clock_gettime(CLOCK_REALTIME, &tmp);
		timespecsub(&timeout, &tmp);
		while (timeout.tv_sec < 0)
			timespecadd(&timeout, &interval);
		if (moep_select(0, NULL, NULL, NULL, &timeout, &oldset) < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "ptmbeacon: error: %s\n", strerror(errno));
				free(args.addr);
				moep_dev_close(rad);
				moep_dev_close(tap);
				return -1;
			}
		}
	}

	sigprocmask(SIG_SETMASK, &oldset, NULL);
	free(args.addr);
	moep_dev_close(rad);
	moep_dev_close(tap);
	return 0;
}
