#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <math.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "acs.h"

struct dl_list freq_list = {
	(&freq_list),
	(&freq_list),
};

__s8 lowest_noise = 100;

/**
 * struct survey_info - channel survey info
 *
 * @freq: center of frequency for the surveyed channel
 * @noise: channel noise in dBm
 * @channel_time: amount of time in ms the radio spent on the channel
 * @channel_time_busy: amount of time in ms the radio detected some signal
 *	that indicated to the radio the channel was not clear
 * @channel_time_rx: amount of time the radio spent receiving data
 * @channel_time_tx: amount of time the radio spent transmitting data
 * @interference_factor: computed interference factor observed on this
 *	channel. This is defined as the ratio of the observed busy time
 *	over the time we spent on the channel, this value is then
 * 	amplified by the noise based on the lowest and highest observed
 * 	noise value on the same frequency. This corresponds to:
 *
 *	---
 *	(busy time - tx time) / (active time - tx time) * 2^(noise + min_noise)
 *	---
 *
 *	The coefficient of of 2 reflects the way power in "far-field" radiation
 *	decreases as the square of distance from the antenna [1]. What this does
 *	is it decreases the observed busy time ratio if the noise observed was
 *	low but increases it if the noise was high, proportionally to the way
 *	"far field" radiation changes over distance. Since the values obtained
 * 	here can vary from fractional to millions the sane thing to do here is
 *	to use log2() to reflect the observed interference factor. log2() values
 *	less than 0 then represent fractional results, while > 1 values non-fractional
 *	results. The computation of the interference factor then becomes:

 *	---
 *	log2( (busy time - tx time) / (active time - tx time) * 2^(noise + min_noise))
 *	--- or due to logarithm identities:
 *	log2(busy time - tx time) - log2(active time - tx time) + log2(2^(noise + min_noise))
 *	---
 *
 *	All this is "interference factor" is purely subjective and ony time will tell how
 *	usable this is. By using the minimum noise floor we remove any possible issues
 *	due to card calibration. The computation of the interference factor then is
 *	dependent on what the card itself picks up as the minimum noise, not an actual
 *	real possible card noise value.
 *
 *	Example output:
 *
 *	2412 MHz: 7.429173
 *	2417 MHz: 10.460830
 *	2422 MHz: 12.671070
 *	2427 MHz: 13.583892
 *	2432 MHz: 13.405357
 *	2442 MHz: 13.566887
 *	2447 MHz: 15.630824
 *	2452 MHz: 14.639748
 *	2457 MHz: 14.139193
 *	2467 MHz: 11.914643
 *	2472 MHz: 16.996074
 *	2484 MHz: 15.175455
 *	5180 MHz: -0.218548
 *	5200 MHz: -2.204059
 *	5220 MHz: -1.762898
 *	5240 MHz: -1.314665
 *	5260 MHz: -3.100989
 *	5280 MHz: -2.157037
 *	5300 MHz: -1.842629
 *	5320 MHz: -1.498928
 *	5500 MHz: 3.304770
 *	5520 MHz: 2.345992
 *	5540 MHz: 2.749775
 *	5560 MHz: 2.390887
 *	5580 MHz: 2.592958
 *	5600 MHz: 2.420149
 *	5620 MHz: 2.650282
 *	5640 MHz: 2.954027
 *	5660 MHz: 2.991007
 *	5680 MHz: 2.955472
 *	5700 MHz: 2.280499
 *	5745 MHz: 2.388630
 *	5765 MHz: 2.332542
 *	5785 MHz: 0.955708
 *	5805 MHz: 1.025377
 *	5825 MHz: 0.843392
 *	Ideal freq: 5260 MHz
 *
 *	[1] http://en.wikipedia.org/wiki/Near_and_far_field
 */
struct freq_survey {
	__u32 ifidx;
	__u16 center_freq;
	__u64 channel_time;
	__u64 channel_time_busy;
	__u64 channel_time_rx;
	__u64 channel_time_tx;
	__s8 noise;
	/* An alternative is to use__float128 for low noise environments */
	long double interference_factor;
	struct dl_list list_member;
};

static struct freq_item *get_freq_item(__u16 center_freq)
{
	struct freq_item *freq;

	dl_list_for_each(freq, &freq_list, struct freq_item, list_member) {
		if (freq->center_freq == center_freq)
			return freq;
	}

	freq = (struct freq_item*) malloc(sizeof(struct freq_item));
	if (!freq)
		return NULL;
	memset(freq, 0, sizeof(struct freq_item));

	freq->center_freq = center_freq;
	dl_list_init(&freq->survey_list);
	dl_list_add_tail(&freq_list, &freq->list_member);

	return freq;
}

static int add_survey(struct nlattr **sinfo, __u32 ifidx)
{
	struct freq_survey *survey;
	struct freq_item *freq;

	survey = (struct freq_survey*) malloc(sizeof(struct freq_survey));
	if  (!survey)
		return -ENOMEM;
	memset(survey, 0, sizeof(struct freq_survey));

	survey->ifidx = ifidx;
	survey->noise = (int8_t) nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
	survey->center_freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
	survey->channel_time = nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]);
	survey->channel_time_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]);
	survey->channel_time_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]);
	survey->channel_time_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]);

	freq = get_freq_item(survey->center_freq);
	if (!freq) {
		free(survey);
		return -ENOMEM;
	}

	if (freq->max_noise < survey->noise)
		freq->max_noise = survey ->noise;

	if (freq->min_noise > survey->noise)
		freq->min_noise = survey->noise;

	if (lowest_noise > survey->noise)
		lowest_noise = survey->noise;

	dl_list_add_tail(&freq->survey_list, &survey->list_member);
	freq->survey_count++;

	return 0;
}

static int check_survey(struct nlattr **sinfo, int freq_filter)
{
	struct freq_item *freq;
	__u32 surveyed_freq;

	if (!sinfo[NL80211_SURVEY_INFO_FREQUENCY]) {
		fprintf(stderr, "bogus frequency!\n");
		return NL_SKIP;
	}

	surveyed_freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);

	freq = get_freq_item(nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]));
	if (!freq)
		return -ENOMEM;

	if (!sinfo[NL80211_SURVEY_INFO_NOISE] ||
	    !sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME] ||
	    !sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY] ||
	    !sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX])
		return NL_SKIP;

	if (freq_filter) {
		if (freq_filter == -1)
			return NL_SKIP;
		if (freq_filter != surveyed_freq)
			return NL_SKIP;
	}

	return 0;
}

int handle_survey_dump(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
	__u32 ifidx;
	int freq;
	int *pfreq = NULL;
	int err;

	static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
		[NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
	};

	if (!arg)
		freq = 0;
	else {
		pfreq = (int *) arg;
		freq = *pfreq;
	}

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

	if (!tb[NL80211_ATTR_SURVEY_INFO]) {
		fprintf(stderr, "survey data missing!\n");
		return NL_SKIP;
	}

	if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
			     tb[NL80211_ATTR_SURVEY_INFO],
			     survey_policy)) {
		fprintf(stderr, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	err = check_survey(sinfo, freq);
	if (err != 0)
		return err;

	add_survey(sinfo, ifidx);

	return NL_SKIP;
}

static __u64 min(__u64 a, __u64 b)
{
	return (a < b) ? a : b;
}

/*
 * Make it fit in the used data type, this is done
 * so that we always have sane values, otherwise the
 * values will go out of bounds. We pick 2^30 as that
 * 2^31 yields -inf on long double -- and we can add
 * log(2^30) + log(2^30) in a long double as well.
 */
static __u64 log2_sane(__u64 val)
{
	return log2(min(1073741824, val));
}

static long double compute_interference_factor(struct freq_survey *survey, __s8 min_noise)
{
	long double factor;

	factor = log2_sane(survey->channel_time_busy - survey->channel_time_tx);
	factor -= log2_sane(survey->channel_time - survey->channel_time_tx);
	factor += survey->noise - min_noise;

	survey->interference_factor = factor;

	return factor;
}

#ifdef VERBOSE
static void parse_survey(struct freq_survey *survey, unsigned int id)
{
	char dev[20];

	if_indextoname(survey->ifidx, dev);

	if (id == 1)
		printf("\n");

	printf("Survey %d from %s:\n", id, dev);

	printf("\tnoise:\t\t\t\t%d dBm\n",
	       (int8_t) survey->noise);
	printf("\tchannel active time:\t\t%llu ms\n",
	       (unsigned long long) survey->channel_time);
	printf("\tchannel busy time:\t\t%llu ms\n",
	       (unsigned long long) survey->channel_time_busy);
	printf("\tchannel receive time:\t\t%llu ms\n",
	       (unsigned long long) survey->channel_time_rx);
	printf("\tchannel transmit time:\t\t%llu ms\n",
	       (unsigned long long) survey->channel_time_tx);
	printf("\tinterference factor:\t\t%Lf\n", survey->interference_factor);
}
#else
static void parse_survey(struct freq_survey *survey, unsigned int id)
{
	printf("%Lf ", survey->interference_factor);
}
#endif

static void parse_freq(struct freq_item *freq)
{
	struct freq_survey *survey;
	unsigned int i = 0;
	long double int_factor = 0, sum = 0;

	if (dl_list_empty(&freq->survey_list) || !freq->enabled)
		return;

	printf("%5d surveys for %d MHz: ", freq->survey_count, freq->center_freq);

	dl_list_for_each(survey, &freq->survey_list, struct freq_survey, list_member) {
		int_factor = compute_interference_factor(survey, lowest_noise);
		sum = freq->interference_factor + int_factor;
		freq->interference_factor = sum;
		parse_survey(survey, ++i);
	}

	freq->interference_factor = freq->interference_factor / freq->survey_count;

	printf("\n");
}

/* At this point its assumed we have the min_noise */
void parse_freq_list(void)
{
	struct freq_item *freq;

	dl_list_for_each(freq, &freq_list, struct freq_item, list_member) {
		parse_freq(freq);
	}
}

void parse_freq_int_factor(void)
{
	struct freq_item *freq, *ideal_freq = NULL;

	dl_list_for_each(freq, &freq_list, struct freq_item, list_member) {
		if (dl_list_empty(&freq->survey_list) || !freq->enabled) {
			continue;
		}

		printf("%d MHz: %Lf\n", freq->center_freq, freq->interference_factor);

		if (!ideal_freq)
			ideal_freq = freq;
		else {
			if (freq->interference_factor < ideal_freq->interference_factor)
				ideal_freq = freq;
		}
	}
	if (ideal_freq)
		printf("Ideal freq: %d MHz\n", ideal_freq->center_freq);
	else
		fprintf(stderr, "invalid ideal freq! list empty.\n");
}

void annotate_enabled_chans(void)
{
	struct freq_item *freq;

	dl_list_for_each(freq, &freq_list, struct freq_item, list_member)
		if (!dl_list_empty(&freq->survey_list))
			freq->enabled = true;
}

static void clean_freq_survey(struct freq_item *freq)
{
	struct freq_survey *survey, *tmp;

	dl_list_for_each_safe(survey, tmp, &freq->survey_list, struct freq_survey, list_member) {
		dl_list_del(&survey->list_member);
		freq->survey_count--;
		free(survey);
	}
}

static void __clean_freq_list(bool clear_freqs)
{
	struct freq_item *freq, *tmp;

	dl_list_for_each_safe(freq, tmp, &freq_list, struct freq_item, list_member) {
		if (clear_freqs)
			dl_list_del(&freq->list_member);
		clean_freq_survey(freq);
		if (clear_freqs)
			free(freq);
	}
}

void clean_freq_list(void)
{
	__clean_freq_list(true);
}

void clear_freq_surveys(void)
{
	__clean_freq_list(false);
}
