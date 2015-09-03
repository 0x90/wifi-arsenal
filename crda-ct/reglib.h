#ifndef REG_LIB_H
#define REG_LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <math.h>

#include "regdb.h"

/* Common regulatory structures, functions and helpers */

/* This matches the kernel's data structures */
struct ieee80211_freq_range {
	uint32_t start_freq_khz;
	uint32_t end_freq_khz;
	uint32_t max_bandwidth_khz;
};

struct ieee80211_power_rule {
	uint32_t max_antenna_gain;
	uint32_t max_eirp;
};

struct ieee80211_reg_rule {
	struct ieee80211_freq_range freq_range;
	struct ieee80211_power_rule power_rule;
	uint32_t flags;
	uint32_t dfs_cac_ms;
};

struct ieee80211_regdomain {
	uint32_t n_reg_rules;
	char alpha2[2];
	uint8_t dfs_region;
	struct ieee80211_reg_rule reg_rules[];
};

#define REGLIB_MHZ_TO_KHZ(freq) ((freq) * 1000)
#define REGLIB_KHZ_TO_MHZ(freq) ((freq) / 1000)
#define REGLIB_DBI_TO_MBI(gain) ((gain) * 100)
#define REGLIB_MBI_TO_DBI(gain) ((gain) / 100)
#define REGLIB_DBM_TO_MBM(gain) ((gain) * 100)
#define REGLIB_MBM_TO_DBM(gain) ((gain) / 100)

#define REGLIB_MW_TO_DBM(gain) (10 * log10(gain))
#define REGLIB_MW_TO_MBM(gain) (REGLIB_DBM_TO_MBM(REGLIB_MW_TO_DBM(gain)))

/**
 * struct reglib_regdb_ctx - reglib regdb context
 *
 * This can be used to interat with reglib without
 * having to open() / close() / mmap() / munmap()
 * and check the regdb binary file for integrity and
 * authorship.
 *
 * @fd: file descriptor of the db
 * @stat: @fd fstat()
 * @db: mmap() of the db of @real_dblen
 * @real_dblen: file size in bytes of @fd
 * @siglen: size in bytes of the signature at the end of the file
 * @dblen: database lenghth, this is the @real_dblen - @siglen
 * @verified: whether or not this regdb has been RSA verified.
 * 	This value is dependent on whether or not you enabled
 * 	signature verification with gcrypt, openssl, or none
 * 	at all. If no signature verification was not compiled
 * 	in then this will always be true otherwise this will
 * 	only be true if the RSA digital signature of the SHA1
 * 	sum of the regulatory database at the end of the
 * 	regulatory database can be verified with the one of
 * 	the trusted public keys.
 */
struct reglib_regdb_ctx {
	int fd;
	struct stat stat;
	uint8_t *db;
	uint32_t real_dblen;
	uint32_t siglen;
	uint32_t dblen;
	bool verified;

	struct regdb_file_header *header;
	uint32_t num_countries;
	struct regdb_file_reg_country *countries;
};

static inline int reglib_is_world_regdom(const char *alpha2)
{
	if (alpha2[0] == '0' && alpha2[1] == '0')
		return 1;
	return 0;
}

static inline int reglib_isalpha_upper(char letter)
{
	if (letter >= 'A' && letter <= 'Z')
		return 1;
	return 0;
}

static inline int reglib_is_alpha2(const char *alpha2)
{
	if (reglib_isalpha_upper(alpha2[0]) && reglib_isalpha_upper(alpha2[1]))
		return 1;
	return 0;
}

static inline int reglib_is_valid_regdom(const char *alpha2)
{
	if (!reglib_is_alpha2(alpha2) && !reglib_is_world_regdom(alpha2))
		return 0;

	return 1;
}

static inline uint32_t reglib_max(uint32_t a, uint32_t b)
{
	return (a > b) ? a : b;
}

static inline uint32_t reglib_min(uint32_t a, uint32_t b)
{
	return (a > b) ? b : a;
}

void *
reglib_get_file_ptr(uint8_t *db, size_t dblen, size_t structlen, uint32_t ptr);
int reglib_verify_db_signature(uint8_t *db, size_t dblen, size_t siglen);

/**
 * reglib_malloc_regdb_ctx - create a regdb context for usage with reglib
 *
 * @regdb_file: file name
 *
 * Most operations on reglib iterate over the database somehow and prior
 * to iterating over it it must check the signature. Use this context helper
 * to let you query the db within different contexts in your program and
 * just be sure to call reglib_free_regdb_ctx() when done. This helper will
 * open the file passed and mmap() it.
 */
const struct reglib_regdb_ctx *reglib_malloc_regdb_ctx(const char *regdb_file);

/**
 * reglib_free_regdb_ctx - free a regdb context used with reglib
 *
 * @regdb_ctx: the reglib regdb context created with reglib_malloc_regdb_ctx()
 *
 * This will do all the handy work to close up, munmap, and free the
 * reglib regdb context passed.
 */
void reglib_free_regdb_ctx(const struct reglib_regdb_ctx *regdb_ctx);

const struct ieee80211_regdomain *
reglib_get_rd_idx(unsigned int idx, const struct reglib_regdb_ctx *ctx);

#define reglib_for_each_country(__rd, __idx, __ctx)		\
	for (__rd = reglib_get_rd_idx(__idx, __ctx);		\
	     __rd != NULL;					\
	     __rd = reglib_get_rd_idx(++__idx, __ctx))		\

const struct ieee80211_regdomain *
reglib_get_rd_alpha2(const char *alpha2, const char *file);

/**
 * reglib_is_valid_rd - validate regulatory domain data structure
 *
 * @rd: regulatory domain data structure to validate
 *
 * You can use this to validate regulatory domain data structures
 * for possible inconsistencies.
 */
int reglib_is_valid_rd(const struct ieee80211_regdomain *rd);

/* reg helpers */
void reglib_print_regdom(const struct ieee80211_regdomain *rd);
struct ieee80211_regdomain *
reglib_intersect_rds(const struct ieee80211_regdomain *rd1,
		     const struct ieee80211_regdomain *rd2);

/**
 * reglib_intersect_regdb - intersects a regulatory database
 *
 * @regdb_file: the regulatory database to intersect
 *
 * Goes through an entire regulatory database and intersects all regulatory
 * domains. This will skip any regulatory marked with an alpha2 of '00', which
 * is used to indicate a world regulatory domain. If intersection is able
 * to find rules that fit all regulatory domains it return a regulatory
 * domain with such rules otherwise it returns NULL.
 */
const struct ieee80211_regdomain *
reglib_intersect_regdb(const struct reglib_regdb_ctx *ctx);

/**
 * @reglib_create_parse_stream - provide a clean new stream for processing
 *
 * @fp: FILE stream, could be stdin, or a stream from an open file.
 *
 * In order to parse a stream we recommend to create a new stream
 * using this helper. A new stream is preferred in order to work
 * with stdin, as otherwise we cannot rewind() and move around
 * the stream. This helper will create new stream using tmpfile()
 * and also remove all comments. It will be closed and the file
 * deleted when the process terminates.
 */
FILE *reglib_create_parse_stream(FILE *fp);

/**
 * @reglib_parse_country - parse stream to build a regulatory domain
 *
 * @fp: FILE stream, could be stdin, or a stream from an open file.
 *
 * Parse stream and return back a built regulatory domain. Returns
 * NULL if one could not be built.
 */
struct ieee80211_regdomain *reglib_parse_country(FILE *fp);

/**
 * @reglib_optimize_regdom - optimize a regulatory domain
 *
 * @rd: a regulatory domain to be optimized
 *
 * A regulatory domain may exist without optimal expressions
 * over its rules. This will look for regulatory rules that can
 * be combined together to reduce the size of the regulatory
 * domain and its expression.
 *
 * Regulatory rules will be combined if their max allowed
 * bandwidth, max EIRP, and flags all match.
 */
struct ieee80211_regdomain *
reglib_optimize_regdom(struct ieee80211_regdomain *rd);

#define reglib_for_each_country_stream(__fp, __rd)		\
	for (__rd = reglib_parse_country(__fp);			\
	     __rd != NULL;					\
	     __rd = reglib_parse_country(__fp))			\

#endif
