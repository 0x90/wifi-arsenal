/*
 * Copyright (c) 2008 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include "ah_regdomain_common.h"

#define CONFIG_DEBUG		0
#define CONFIG_PRINT_TURBO	0
#define CONFIG_NEW_DFS_RULES	1
#define CONFIG_NEW_JAPAN_RULES	1
#define CONFIG_NEW_CANADA_RULES	1
#define CONFIG_NEW_AU_RULES	1
#define CONFIG_NEW_KR_RULES	1 /* Korea */

#if CONFIG_DEBUG
#define DEBUG_PRINT(fmt, ...) do { \
	printf(fmt, ##__VA_ARGS__); \
	} while (0)
#else
#define DEBUG_PRINT(fmt, ...) do { /* nothing */ } while(0)
#endif

/*
 * Test to see if the bitmask array is all zeros
 */
static int 
isChanBitMaskZero(u_int64_t *bitmask)
{
	int i;

	for (i=0; i<BMLEN; i++) {
		if (bitmask[i] != 0)
			return 0;
	}
	return 1;
}


/*
 * Find the country code.
 */
u_int16_t
findCountryCode(u_int8_t *countryString)
{
	int i;

	for (i=0; i<array_size(allCountries); i++) {
		if ((allCountries[i].isoName[0] == countryString[0]) &&
		    (allCountries[i].isoName[1] == countryString[1]))
			return (allCountries[i].countryCode);
	}
	return (0);		/* Not found */
}


/*
 * Find the pointer to the country element in the country table
 * corresponding to the country code
 */
static struct country_code_to_enum_rd*
findCountry(u_int16_t countryCode)
{
	int i;

	for (i=0; i<array_size(allCountries); i++) {
		if (allCountries[i].countryCode == countryCode)
			return (&allCountries[i]);
	}
	return 0;		/* Not found */
}

static int
is_bit_set(int bit, u_int64_t *bitmask)
{
	int byteOffset, bitnum;
	u_int64_t val;

	byteOffset = bit/64;
	bitnum = bit - byteOffset*64;
	val = ((u_int64_t) 1) << bitnum;
	if (bitmask[byteOffset] & val)
		return 1;
	else
		return 0;
}

static struct reg_dmn_pair_mapping *
find_reg_pair_map(u_int16_t reg)
{
	int i;
	for (i=0; i<array_size(regDomainPairs); i++) {
		if (regDomainPairs[i].regDmnEnum == reg)
			return (&regDomainPairs[i]);
	}
	return 0;
}

static struct reg_domain *
find_regd(u_int16_t regd)
{
	int i;
	for (i=0; i<array_size(regdomains); i++) {
		if (regdomains[i].regDmnEnum == regd)
			return (&regdomains[i]);
	}
	return 0;
}

static u_int8_t
print_ctl(u_int8_t ctl)
{
	switch (ctl) {
		case FCC:
			return 1;
			break;
		case ETSI:
			return 2;
			break;
		case MKK:
			return 3;
			break;
		case NO_CTL:
			return 0;
		default:
			return 10; /* Should not happen */
	}
	return 0;
}

static inline int
is_reg_5ghz(struct reg_domain *regd)
{
	if (regd->chan11a[0] || regd->chan11a[1])
		return 1;
	if (regd->chan11a_turbo[0] || regd->chan11a_turbo[1])
		return 1;
	if (regd->chan11a_dyn_turbo[0] || regd->chan11a_dyn_turbo[1])
		return 1;
	return 0;
}

static inline int
is_reg_2ghz(struct reg_domain *regd)
{
	if (regd->chan11b[0] || regd->chan11b[1])
		return 1;
	if (regd->chan11g[0] || regd->chan11g[1])
		return 1;
	if (regd->chan11g_turbo[0] || regd->chan11g_turbo[1])
		return 1;
	return 0;
}

static void
print_country_flags(struct reg_domain *regd,
	struct country_code_to_enum_rd *rd)
{
	if (is_reg_5ghz(regd)) {
		if (! rd->allow11na40)
			printf(", NO-HT40");
	}
	else if (is_reg_2ghz(regd)) {
		if (! rd->allow11ng40)
			printf(", NO-HT40");
	}
	else
		printf("BUG - regd determined to not be 2ghz or 5ghz...\n");
	printf("\n");

	/* outdoorChanStart seems useless, its always = 7000 */
}

#if CONFIG_PRINT_TURBO
static void
print_regd_flags_turbo(struct reg_domain *regd)
{
	if (regd->flags & DISALLOW_ADHOC_11A_TURB)
		printf(", REQ_DISALLOW_ADHOC_11A_TURB");
}
#else
static inline int
print_regd_flags_turbo(struct reg_domain *regd)
{
	return;
}
#endif /* CONFIG_PRINT_TURBO */

static void
print_regd_flags(struct reg_domain *regd)
{
	/* XXX: Finish printing out flags per regd */
/*
	printf(", EDGE-POWER-%d", print_ctl(regd->conformanceTestLimit));	
*/
	if (regd->flags & NO_REQ) {
		return;
	}
	/* Note: we ignore NEED_NFC as per advise that we
	 * already do noise floor anyway */

	/* Note: DISALLOW_ADHOC_11A is no IBSS on 802.11a but
	 * since we are printing the flags per frequency range
	 * and since this flag is per major band pair
	 * (2ghz or 5 ghz) there is no need to make it
	 * IEEE-802.11 sepecific, just say NO-IBSS
	 */

	/* This takes into consideration of new DFS rules
	 * as per Michael Green */
#ifndef CONFIG_NEW_DFS_RULES
	if (regd->flags & DISALLOW_ADHOC_11A)
		printf(", NO-IBSS");
#endif
	if (regd->flags & ADHOC_PER_11D)
		printf(", REQ-ADHOC_PER-11D");
#ifndef CONFIG_NEW_DFS_RULES
	if (regd->flags & ADHOC_NO_11A)
		printf(", NO-IBSS2");
#endif
	if (regd->flags & PUBLIC_SAFETY_DOMAIN)
		printf(", REQ-PUBLIC-SAFETY-DOMAIN");
	if (regd->flags & LIMIT_FRAME_4MS)
		printf(", REQ-LIMIT_FRAME-4MS");
	if (regd->flags & NO_HOSTAP)
		printf(", REQ-NO-HOSTAP");

	print_regd_flags_turbo(regd);
}

#define IS_DFS_FREQ(freq) (freq >= 5260 && freq <= 5700)

/* Both of the structures here have passive scan and DFS flags.
 * To deal with them -inline- we use this routine. */
static void
print_common_regd_freq_flags(struct reg_domain *regd,
		struct reg_dmn_freq_band *freq,
		struct reg_dmn_pair_mapping *reg_pair_map)
{
	u_int64_t pscan;
	pscan = regd->pscan & reg_pair_map->pscanMask;
	 
	/* As per Michael Green, these are the new DFS rules */
#ifndef CONFIG_NEW_DFS_RULES
	 if (freq->usePassScan & pscan)
		 printf(", PASSIVE-SCAN");
	 if (freq->useDfs & regd->dfsMask)
		 printf(", DFS");
#endif
}

#if CONFIG_PRINT_TURBO
static int
can_print_from_freq_coll_turbo(struct reg_dmn_freq_band *freq_coll)
{
	if (freq_coll == regDmn5GhzTurboFreq)
		return 1;
	else if (freq_coll == regDmn5GhzTurboFreq)
		return 1;
	else if (freq_coll == regDmn2Ghz11gTurboFreq)
		return 1;
	else
		return 0;
}
#else
static inline int
can_print_from_freq_coll_turbo(struct reg_dmn_freq_band *freq_coll)
{
	return 0;
}
#endif /* CONFIG_PRINT_TURBO */

static int
can_print_from_freq_coll(struct reg_dmn_freq_band *freq_coll) {
	if (freq_coll == regdmn5ghzfreq)
		return 1;
	else if (freq_coll == regDmn2GhzFreq)
		return 1;
	else if (freq_coll == regDmn2Ghz11gFreq)
		return 1;
	else {
		if (can_print_from_freq_coll_turbo(freq_coll))
			return 1;
		else
			return 0;
	}
	return 0;
}

/* XXX: I tried to remove this macro but can't figure a clean
 * way to pass the freq_collection in such as way the receiver
 * call iterate over it */
#define PRINT_FREQ(bitmap, freq_collection) \
		size_of_collection = array_size(freq_collection); \
		DEBUG_PRINT("Array size: %d\n", size_of_collection); \
		if (is_bit_set(i, bitmap)) { \
			if (i > size_of_collection)  { \
				printf("BUG - bit (%d) out of " \
					"bounds on bitmap %s\n", i, #bitmap); \
			} \
			else { \
				DEBUG_PRINT("Channels on %s\n", #bitmap); \
				if (can_print_from_freq_coll(freq_collection)) { \
					char antenna_gain[5]; \
					struct reg_dmn_freq_band *freq = \
						&freq_collection[i]; \
					if (freq->antennaMax == 0) \
						sprintf(antenna_gain, "N/A"); \
					else \
						sprintf(antenna_gain, "%d", freq->antennaMax); \
					printf(	"\t(%d - %d @ %d), " \
						"(%s, %d)", \
						freq->lowChannel - (freq->channelBW/2), \
						freq->highChannel + (freq->channelBW/2), \
						freq->channelBW, \
						antenna_gain, \
						freq->powerDfs \
						); \
						print_common_regd_freq_flags(regd, freq, reg_pair_map); \
						print_regd_flags(regd); \
						print_country_flags(regd, rd); \
				} \
			} \
		}

static void
print_regd(struct reg_domain *regd,
	struct country_code_to_enum_rd *rd,
	struct reg_dmn_pair_mapping *reg_pair_map)
{
	int i;

	/* Each frequency can have 128 frequency ranges. As it stands
	 * 5 GHz has 64 frequency ranges defined, 2 GHz has a lot less.
	 * After a 64 bits has been used is_bit_set() converts the bit
	 * number to an array index offset. We only support 2 right now, 
	 * each holding 64 bits.
	 */

	for (i=0; i<128; i++) {
		int size_of_collection = 0;

		DEBUG_PRINT("On bit #%d\n", i);

		/* We deal with not printing turbo through compile flags.
		 * This is in case we later want to add this to a private
		 * CRDA DB. */
		PRINT_FREQ(regd->chan11a,		regdmn5ghzfreq);
		PRINT_FREQ(regd->chan11a_turbo,		regDmn5GhzTurboFreq);
		PRINT_FREQ(regd->chan11a_dyn_turbo,	regDmn5GhzTurboFreq);
		PRINT_FREQ(regd->chan11b,		regDmn2GhzFreq);
		PRINT_FREQ(regd->chan11g,		regDmn2Ghz11gFreq);
		PRINT_FREQ(regd->chan11g_turbo,		regDmn2Ghz11gTurboFreq);
	}

}

int main(int argc, char **argv) {
	int i;
	int same_freq_count, prev_low, prev_high;
	u_int16_t country_code;

	if (argc != 1 && argc != 2) {
		printf("Usage: dump_ah_regdb [country_alpha2]\n");
		printf("Examples:\n");
		printf("\tThis dumps the entire db:\n");
		printf("\tdump_ah_regdb\n");
		printf("\tThis dumps info only for US\n");
		printf("\tdump_ah_regdb US\n");
		return 1;
	}

	/* This print should match CRDA db.txt as much as possible
	 * git://git.kernel.org/pub/scm/linux/kernel/git/mcgrof/crda.git */

	if (argc == 2) {
		struct country_code_to_enum_rd *rd;
		struct reg_dmn_pair_mapping *reg_pair_map;
		struct reg_domain *regd_5ghz;
		struct reg_domain *regd_2ghz;

		country_code = findCountryCode(argv[1]);
		rd = findCountry(country_code);
		if (!rd) {
			printf("Regdomain not found\n");
			return 1;
		}

		if (strcmp(argv[1], rd->isoName) != 0) {
				printf("No match found\n");
				return 1;
		}

#ifdef CONFIG_NEW_JAPAN_RULES
		if (strcmp("JP", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case MKK5_MKKA2:
				case MKK5_MKKC:
				case MKK11_MKKA2:
				case MKK11_MKKC:
					break; /* allowed */
				default:
					/* XXX: we should just iterate over the DB
					 * until we found all 4 of the above and print them */
					printf("Outdated regulatory domain detected for JP (0x%X),\n"
						"the first JP regdomain needs to be updated.\n"
						"Valid regulatory domains:\n"
						"\t0x%X, 0x%X, 0x%X, 0x%X\n",
						rd->regDmnEnum,
						MKK5_MKKA2,
						MKK5_MKKC,
						MKK11_MKKA2,
						MKK11_MKKC);
					return 1;
			}
		}
#endif
#ifdef CONFIG_NEW_CANADA_RULES
		if (strcmp("CA", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case FCC3_FCCA:
					break; /* allowed */
				default:
					/* XXX: we should just iterate over the DB
					 * until we find the one above and print it */
					printf("Outdated regulatory domain detected for CA (0x%X),\n"
						"the first CA regdomain needs to be updated.\n"
						"Valid regulatory domain: 0x%X\n",
						rd->regDmnEnum, FCC3_FCCA);
					return 1;
			}
		}
#endif
#ifdef CONFIG_NEW_AU_RULES
		if (strcmp("AU", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case FCC2_WORLD:
					break; /* allowed */
				default:
					/* XXX: we should just iterate over the DB
					 * until we find the one above and print it */
					printf("Outdated regulatory domain detected for AU (0x%X),\n"
						"the first CA regdomain needs to be updated.\n"
						"Valid regulatory domain: 0x%X\n",
						rd->regDmnEnum, FCC2_WORLD);
					return 1;
			}
		}
#endif
#ifdef CONFIG_NEW_KR_RULES
		if ((strcmp("K2", rd->isoName) == 0)  ||
			(strcmp("K3", rd->isoName) == 0)) {
			printf("K2 and K3 are not supported with new reg rules\n");
			return 1;
		}
		if (strcmp("KR", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case APL10_WORLD:
					break; /* allowed */
				default:
					/* XXX: we should just iterate over the DB
					 * until we find the one above and print it */
					printf("Outdated regulatory domain detected for KR (0x%X),\n"
						"the first CA regdomain needs to be updated.\n"
						"Valid regulatory domain: 0x%X\n",
						rd->regDmnEnum, APL10_WORLD);
					return 1;
			}
		}
#endif

		printf("country %s:\n", rd->isoName);

		reg_pair_map = find_reg_pair_map(rd->regDmnEnum);
		if (!reg_pair_map) {
			printf("Regdomain pair map not found\n");
			return 1;
		}

		regd_5ghz = find_regd(reg_pair_map->regDmn5GHz);
		regd_2ghz = find_regd(reg_pair_map->regDmn2GHz);

		print_regd(regd_5ghz, rd, reg_pair_map);
		print_regd(regd_2ghz, rd, reg_pair_map);

		printf("\n\n");

		return 0;
	}

	/* Print all frequency ranges (called a "band" in db.txt */

	/* For upstream CRDA db.txt we don't need Turbo channels,
	 * they are not used for HT20 or HT40. To prevent its print we
	 * use can_print_from_freq_coll() as a check */

	for (i=0; i<array_size(allCountries); i++) {
		struct country_code_to_enum_rd *rd;
		struct reg_dmn_pair_mapping *reg_pair_map;
		struct reg_domain *regd_5ghz;
		struct reg_domain *regd_2ghz;

		rd = &allCountries[i];
		if (!rd) {
			printf("Regdomain not found\n");
			return 1;
		}

#ifdef CONFIG_NEW_JAPAN_RULES
		if (strcmp("JP", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case MKK5_MKKA2:
				case MKK5_MKKC:
				case MKK11_MKKA2:
				case MKK11_MKKC:
					/* allowed */
					break;
				default:
					/* Not allowed, skip */
					continue;
			}
		}
#endif
#ifdef CONFIG_NEW_CANADA_RULES
		if (strcmp("CA", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case FCC3_FCCA:
					/* allowed */
					break;
				default:
					/* Not allowed, skip */
					continue;
			}
		}
#endif
#ifdef CONFIG_NEW_AU_RULES
		if (strcmp("AU", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case FCC2_WORLD:
					/* allowed */
					break;
				default:
					/* Not allowed, skip */
					continue;
			}
		}
#endif
#ifdef CONFIG_NEW_KR_RULES
		if ((strcmp("K2", rd->isoName) == 0)  ||
			(strcmp("K3", rd->isoName) == 0)) {
			continue;
		}
		if (strcmp("KR", rd->isoName) == 0) {
			switch(rd->regDmnEnum) {
				case APL10_WORLD:
					/* allowed */
					break;
				default:
					/* Not allowed, skip */
					continue;
			}
		}
#endif

		printf("country %s:\n", rd->isoName);

		reg_pair_map = find_reg_pair_map(rd->regDmnEnum);
		if (!reg_pair_map) {
			printf("Regdomain pair map not found\n");
			return 1;
		}

		regd_5ghz = find_regd(reg_pair_map->regDmn5GHz);
		regd_2ghz = find_regd(reg_pair_map->regDmn2GHz);

		print_regd(regd_5ghz, rd, reg_pair_map);
		print_regd(regd_2ghz, rd, reg_pair_map);

		printf("\n");
	}
	return 0;
}
