#ifndef REG_DB_H
#define REG_DB_H

#include <stdint.h>

/*
 * WARNING: This file needs to be kept in sync with
 *  - the parser (dbparse.py)
 *  - the generator code (db2bin.py)
 *
 * As it is only Linux is using these so we have a direct one to
 * one map for flags. Each respective OS flag is listed where
 * appropriate.
 */

/* spells "RGDB" */
#define REGDB_MAGIC	0x52474442

/*
 * Only supported version now, start at arbitrary number
 * to have some more magic. We still consider this to be
 * "Version 1" of the file.
 */
#define REGDB_VERSION	19

/*
 * The signature at the end of the file is an RSA-signed
 * SHA-1 hash of the file.
 */

/* db file starts with a struct regdb_file_header */

struct regdb_file_header {
	/* must be REGDB_MAGIC */
	uint32_t	magic;
	/* must be REGDB_VERSION */
	uint32_t	version;
	/*
	 * Pointer (offset) into file where country list starts
	 * and number of countries. The country list is sorted
	 * alphabetically to allow binary searching (should it
	 * become really huge). Each country is described by a
	 * struct regdb_file_reg_country.
	 */
	uint32_t	reg_country_ptr;
	uint32_t	reg_country_num;
	/* length (in bytes) of the signature at the end of the file */
	uint32_t	signature_length;
};

struct regdb_file_freq_range {
	uint32_t	start_freq,	/* in kHz */
		end_freq,	/* in kHz */
		max_bandwidth;	/* in kHz */
};

/*
 * Values of zero mean "not applicable", i.e. the regulatory
 * does not limit a certain value.
 */
struct regdb_file_power_rule {
	/* antenna gain is in mBi (100 * dBi) */
	uint32_t	max_antenna_gain;
	/* this is in mBm (100 * dBm) */
	uint32_t	max_eirp;
};

/*
 * The Linux map defined in <linux/uapi/nl80211.h> enum nl80211_reg_rule_flags
 */
enum reg_rule_flags {
	RRF_NO_OFDM		= 1<<0, /* OFDM modulation not allowed */
	RRF_NO_CCK		= 1<<1, /* CCK modulation not allowed */
	RRF_NO_INDOOR		= 1<<2, /* indoor operation not allowed */
	RRF_NO_OUTDOOR		= 1<<3, /* outdoor operation not allowed */
	RRF_DFS			= 1<<4, /* DFS support is required to be
					 * used */
	RRF_PTP_ONLY		= 1<<5, /* this is only for Point To Point
					 * links */
	RRF_PTMP_ONLY		= 1<<6, /* this is only for Point To Multi
					 * Point links */
	RRF_NO_IR		= 1<<7, /* do not initiate radiation */
	__RRF_NO_IBSS		= 1<<8, /* old no-IBSS rule, maps to no-ir */
	RRF_AUTO_BW		= 1<<11, /* Auto BW calculations */
};

#define RRF_NO_IR_ALL	(RRF_NO_IR | __RRF_NO_IBSS)

/**
 * enum regdb_dfs_regions - regulatory DFS regions
 *
 * @REGDB_DFS_UNSET: Country has no DFS master region specified
 * @REGDB_DFS_FCC: Country follows DFS master rules from FCC
 * @REGDB_DFS_ETSI: Country follows DFS master rules from ETSI
 * @REGDB_DFS_JP: Country follows DFS master rules from JP/MKK/Telec
 */
enum regdb_dfs_regions {
	REGDB_DFS_UNSET	= 0,
	REGDB_DFS_FCC	= 1,
	REGDB_DFS_ETSI	= 2,
	REGDB_DFS_JP	= 3,
};

struct regdb_file_reg_rule {
	/* pointers (offsets) into the file */
	uint32_t	freq_range_ptr; /* pointer to a struct regdb_file_freq_range */
	uint32_t	power_rule_ptr; /* pointer to a struct regdb_file_power_rule */
	/* rule flags using enum reg_rule_flags */
	uint32_t flags;
};

struct regdb_file_reg_rules_collection {
	uint32_t	reg_rule_num;
	/* pointers (offsets) into the file. There are reg_rule_num elements
	 * in the reg_rule_ptrs array pointing to struct
	 * regdb_file_reg_rule */
	uint32_t	reg_rule_ptrs[];
};

struct regdb_file_reg_country {
	uint8_t	alpha2[2];
	uint8_t	PAD;
	uint8_t	creqs; /* first two bits define DFS region */
	/* pointer (offset) into the file to a struct
	 * regdb_file_reg_rules_collection */
	uint32_t	reg_collection_ptr;
};


/*
 * Verify that no unexpected padding is added to structures
 * for some reason.
 */

#define ERROR_ON(cond) \
	((void)sizeof(char[1 - 2*!!(cond)]))

#define CHECK_STRUCT(name, size) \
	ERROR_ON(sizeof(struct name) != size)

static inline void check_db_binary_structs(void)
{
	CHECK_STRUCT(regdb_file_header, 20);
	CHECK_STRUCT(regdb_file_freq_range, 12);
	CHECK_STRUCT(regdb_file_power_rule, 8);
	CHECK_STRUCT(regdb_file_reg_rule, 12);
	CHECK_STRUCT(regdb_file_reg_rules_collection, 4);
	CHECK_STRUCT(regdb_file_reg_country, 8);
}

#endif
