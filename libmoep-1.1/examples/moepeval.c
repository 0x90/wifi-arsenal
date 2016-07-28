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

#include <arpa/inet.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include <sys/eventfd.h>

#include <moep80211/system.h>
#include <moep80211/types.h>
#include <moep80211/ieee80211_addr.h>

#include <moep80211/modules/moep80211.h>

#include "../src/util.h"


const char *argp_program_version = "moepeval 1.0";
const char *argp_program_bug_address = "<leclaire@in.tum.de>";

static char args_doc[] = "IF1 IF2";

static char doc[] =
"moepeval - a feature evaluator for moep80211\n\n"
"  IF1                        Radio interface number 1\n"
"  IF2                        Radio interface number 2";

enum fix_args {
	FIX_ARG_IF1 = 0,
	FIX_ARG_IF2 = 1,
	FIX_ARG_CNT
};

static struct argp_option options[] = {
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
	char *if1;
	char *if2;
};


#define DEFAULT_MTU 500
#define DEFAULT_CHAN chan_freq[0]

static u64 chan_freq[] = {
	2412,
	2417,
	2422,
	2427,
	2432,
	2437,
	2442,
	2447,
	2452,
	2457,
	2462,
	2467,
	2472,
	2484,

	5180,
	5200,
	5220,
	5240,
	5260,
	5280,
	5300,
	5320,

	5500,
	5520,
	5540,
	5560,
	5580,
	5600,
	5620,
	5640,
	5660,
	5680,
	5700,

	5735,
	5755,
	5775,
	5795,
	5815,
	5835,
	5855,
};

int legacy_rates[] = {
	2, 4, 11, 12, 18, 22, 24, 36, 48, 72, 96, 108
};

static int legacy_idx(int rate)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(legacy_rates); i++) {
		if (legacy_rates[i] == rate)
			return i;
	}
	return -1;
}


static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *args = state->input;

	switch (key) {
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case FIX_ARG_IF1:
			args->if1 = arg;
			break;
		case FIX_ARG_IF2:
			args->if2 = arg;
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


static int dev_avail(const char *name)
{
	moep_dev_t dev;

	if (!(dev = moep_dev_moep80211_open(name, DEFAULT_CHAN,
					    MOEP80211_CHAN_WIDTH_20_NOHT, 0, 0,
					    DEFAULT_MTU))) {
		fprintf(stderr, "cannot create device on '%s': %s\n", name, strerror(errno));
		return -1;
	}
	moep_dev_close(dev);

	return 0;
}

static int max_mtu(const char *name)
{
	moep_dev_t dev;
	int i, step;

	for (i = DEFAULT_MTU, step = i/2; 1; i += step) {
		if (!step)
			break;
		if (!(dev = moep_dev_moep80211_open(name, DEFAULT_CHAN,
						    MOEP80211_CHAN_WIDTH_20_NOHT,
						    0, 0, i))) {
			i -= step;
			step /= 2;
			continue;
		}
		moep_dev_close(dev);
		printf("\rmax MTU %s: %d", name, i);
		fflush(stdout);
	}
	printf("\n");

	return i;
}

static int avail_channels(const char *name)
{
	moep_dev_t dev;
	int i;
	u64 chan;

	chan = 0;
	printf("available channels %s: ", name);
	for (i = 0; i < ARRAY_SIZE(chan_freq); i++) {
		if (!(dev = moep_dev_moep80211_open(name, chan_freq[i],
						    MOEP80211_CHAN_WIDTH_20_NOHT,
						    0, 0, DEFAULT_MTU))) {
			printf("-");
			fflush(stdout);
			continue;
		}
		moep_dev_close(dev);
		chan |= BIT(i);
		printf("+");
		fflush(stdout);
	}
	printf("\n");

	return chan;
}

static u8 data_rate_work_payload[] = "This is the payload";

struct moep_hdr_pctrl data_rate_hdr_pctrl = {
	.hdr = {
		.type = MOEP_HDR_PCTRL,
		.len = sizeof(struct moep_hdr_pctrl),
	},
	.type = htole16(0),
	.len = htole16(sizeof(data_rate_work_payload)),
};

static u16 legacy_rate_worked;
static u32 mcs_rate_worked;

static void rx_handler_work(moep_dev_t dev, moep_frame_t frame)
{
	struct moep80211_radiotap *radiotap;
	struct moep80211_hdr *hdr;
	struct moep_hdr_pctrl *pctrl;

	if (!(hdr = moep_frame_moep80211_hdr(frame))) {
		moep_frame_destroy(frame);
		return;
	}
	if (hdr->frame_control !=
	    htole16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA)) {
		moep_frame_destroy(frame);
		return;
	}

	if (!(pctrl = (struct moep_hdr_pctrl *)moep_frame_moep_hdr_ext(frame, MOEP_HDR_PCTRL))) {
		moep_frame_destroy(frame);
		return;
	}
	if (pctrl->hdr.len != sizeof(struct moep_hdr_pctrl)) {
		moep_frame_destroy(frame);
		return;
	}
	if (pctrl->len != htole16(sizeof(data_rate_work_payload))) {
		moep_frame_destroy(frame);
		return;
	}
	if (pctrl->type != htole16(0)) {
		moep_frame_destroy(frame);
		return;
	}

	// TODO validate payload

	if (!(radiotap = moep_frame_radiotap(frame))) {
		moep_frame_destroy(frame);
		return;
	}
	if (radiotap->hdr.it_present & BIT(IEEE80211_RADIOTAP_RATE))
		legacy_rate_worked |= BIT(legacy_idx(radiotap->rate));
	if ((radiotap->hdr.it_present & BIT(IEEE80211_RADIOTAP_MCS)) &&
	    (radiotap->mcs.known & IEEE80211_RADIOTAP_MCS_HAVE_MCS))
		mcs_rate_worked |= BIT(radiotap->mcs.mcs);

	moep_frame_destroy(frame);
}

static void test_data_rates_work(const char *name1, const char *name2, u64 freq)
{
	moep_dev_t dev1, dev2;
	int i, k;
	struct timespec timeout;
	moep_frame_t frame;
	struct moep80211_radiotap *radiotap;
	struct moep80211_hdr *hdr;
	int event_all;

	printf("%s -> %s, %ld MHz: ", name1, name2, freq);

	if (!(dev1 = moep_dev_moep80211_open(name1, freq,
					     MOEP80211_CHAN_WIDTH_20_NOHT, 0, 0,
					     DEFAULT_MTU))) {
		fprintf(stderr, "cannot create device on %s, %s\n", name1, strerror(errno));
		return;
	}
	if (!(dev2 = moep_dev_moep80211_open(name2, freq,
					     MOEP80211_CHAN_WIDTH_20_NOHT, 0, 0,
					     DEFAULT_MTU))) {
		fprintf(stderr, "cannot create device on %s, %s\n", name2, strerror(errno));
		moep_dev_close(dev1);
		return;
	}
	moep_dev_set_rx_handler(dev2, rx_handler_work);
	if ((event_all = eventfd(1, EFD_NONBLOCK | EFD_SEMAPHORE)) < 0) {
		fprintf(stderr, "cannot create eventfd, %s\n", strerror(errno));
		moep_dev_close(dev1);
		moep_dev_close(dev2);
		return;
	}
	moep_dev_set_rx_event(dev2, event_all);

	if (!(frame = moep_dev_frame_create(dev1))) {
		fprintf(stderr, "cannot create frame, %s\n", strerror(errno));
		moep_dev_close(dev1);
		moep_dev_close(dev2);
		close(event_all);
		return;
	}

	if (!(radiotap = moep_frame_radiotap(frame)))
		goto out;
	radiotap->hdr.it_version = 0;

	if (!(hdr = moep_frame_moep80211_hdr(frame)))
		goto out;
	hdr->frame_control = htole16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);
	memcpy(hdr->ra, "\xde\xad\xbe\xef\x02\x01", sizeof(hdr->ra));
	memcpy(hdr->ta, "\xde\xad\xbe\xef\x02\x02", sizeof(hdr->ta));

	if (!moep_frame_set_moep_hdr_ext(frame, &data_rate_hdr_pctrl.hdr))
		goto out;

	if (!moep_frame_set_payload(frame, data_rate_work_payload,
				    sizeof(data_rate_work_payload)))
		goto out;

	for (k = 0; k < 10; k++) {
		for (i = 0; i < ARRAY_SIZE(legacy_rates); i++) {
			radiotap->rate = legacy_rates[i];
			radiotap->hdr.it_present = BIT(IEEE80211_RADIOTAP_RATE);
			if (moep_dev_tx(dev1, frame)) {
				printf("transmitting packet with data rate %f "
				       "MBit/s failed: %s\n",
				       (float)legacy_rates[i] / 2,
				       strerror(errno));
			};
		}
		for (i = 0; i < 32; i++) {
			radiotap->mcs.mcs = i;
			radiotap->mcs.flags = IEEE80211_RADIOTAP_MCS_BW_20
					   | IEEE80211_RADIOTAP_MCS_SGI;
			radiotap->mcs.known = IEEE80211_RADIOTAP_MCS_HAVE_MCS
					   | IEEE80211_RADIOTAP_MCS_HAVE_BW
					   | IEEE80211_RADIOTAP_MCS_HAVE_GI;
			radiotap->hdr.it_present = BIT(IEEE80211_RADIOTAP_MCS);
			if (moep_dev_tx(dev1, frame)) {
				printf("transmitting packet with MCS index %d "
				       "failed: %s\n", i, strerror(errno));
			}
		}
	}

	timeout.tv_sec = 1;
	timeout.tv_nsec = 0;

	legacy_rate_worked = 0;
	mcs_rate_worked = 0;

	moep_select(0, NULL, NULL, NULL, &timeout, NULL);

	for (i = 0; i < ARRAY_SIZE(legacy_rates); i++) {
		if (legacy_rate_worked & BIT(i)) {
			printf("+");
		} else {
			printf("-");
		}
	}
	printf("|");
	for (i = 0; i < 32; i++) {
		if (mcs_rate_worked & BIT(i)) {
			printf("+");
		} else {
			printf("-");
		}
	}
	printf("\n");

out:
	moep_frame_destroy(frame);
	moep_dev_close(dev1);
	moep_dev_close(dev2);
	close(event_all);
}

int main(int argc, char **argv)
{
	struct arguments args;
	u64 chan1, chan2;
	int i;

	memset(&args, 0, sizeof(args));
	argp_parse(&argp, argc, argv, 0, 0, &args);

	if (dev_avail(args.if1))
		return -1;
	if (dev_avail(args.if2))
		return -1;

	printf("Computing maximum MTU...\n");
	max_mtu(args.if1);
	max_mtu(args.if2);

	printf("Testing available channels...\n");
	chan1 = avail_channels(args.if1);
	chan2 = avail_channels(args.if2);

	printf("Testing working rates...\n");
	for (i = 0; i < ARRAY_SIZE(chan_freq); i++) {
		if (chan1 & chan2 & BIT(i))
			test_data_rates_work(args.if1, args.if2, chan_freq[i]);
	}
	for (i = 0; i < ARRAY_SIZE(chan_freq); i++) {
		if (chan1 & chan2 & BIT(i))
			test_data_rates_work(args.if2, args.if1, chan_freq[i]);
	}

	return 0;
}
