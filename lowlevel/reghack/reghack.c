/*
 * reghack - Utility to binary-patch the embedded mac80211 regulatory rules.
 *
 *   Copyright (C) 2012-2014 Jo-Philipp Wich <xm@subsignal.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <byteswap.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/mman.h>


static int need_byteswap = 0;

enum nl80211_dfs_regions {
	NL80211_DFS_UNSET = 0,
	NL80211_DFS_FCC = 1
};

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
    enum nl80211_dfs_regions dfs_region;
    struct ieee80211_reg_rule reg_rules[1];
};

#define MHZ_TO_KHZ(freq) ((freq) * 1000)
#define KHZ_TO_MHZ(freq) ((freq) / 1000)
#define DBI_TO_MBI(gain) ((gain) * 100)
#define MBI_TO_DBI(gain) ((gain) / 100)
#define DBM_TO_MBM(gain) ((gain) * 100)
#define MBM_TO_DBM(gain) ((gain) / 100)

#define REG_RULE(start, end, bw, gain, eirp, reg_flags) \
{                           \
    .freq_range.start_freq_khz = MHZ_TO_KHZ(start), \
    .freq_range.end_freq_khz = MHZ_TO_KHZ(end), \
    .freq_range.max_bandwidth_khz = MHZ_TO_KHZ(bw), \
    .power_rule.max_antenna_gain = DBI_TO_MBI(gain),\
    .power_rule.max_eirp = DBM_TO_MBM(eirp),    \
    .flags = reg_flags,             \
    .dfs_cac_ms = 0, \
}

#define REG_MATCH(code, num, dfs, rule) \
{ \
	.alpha2 = code, \
	.dfs_region = dfs, \
	.n_reg_rules = num, \
	.reg_rules = { \
		rule \
	} \
}


struct search_regdomain {
	const char *desc;
	struct ieee80211_regdomain reg;
};

static const struct search_regdomain search_regdomains[] = {
	/* cfg80211.ko matches */
	{
		.desc = "core world5 regdomain in cfg80211/reg.o",
		.reg  = REG_MATCH("00", 5, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 6, 20, 0))
	}, {
		.desc = "core world6 regdomain in cfg80211/reg.o",
		.reg  = REG_MATCH("00", 6, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 6, 20, 0))
	}, {
		.desc = "embedded 00 regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("00", 5, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 3, 20, 0))
	}, {
		.desc = "embedded 00 regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("00", 6, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 3, 20, 0))
	}, {
		.desc = "embedded 00 regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("00", 8, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 0, 20, 0))
	}, {
		.desc = "embedded US regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("US", 6, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 3, 27, 0))
	}, {
		.desc = "embedded US regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("US", 7, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 3, 27, 0))
	}, {
		.desc = "embedded US regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("US", 7, NL80211_DFS_FCC, REG_RULE(2402, 2472, 40, 3, 27, 0))
	},

	/* regdb.txt matches (new) */
	{
		.desc = "embedded 00 regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("00", 6, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 0, 20, 0))
	}, {
		.desc = "embedded US regdomain in cfg80211/regdb.o",
		.reg  = REG_MATCH("US", 5, NL80211_DFS_FCC, REG_RULE(2402, 2472, 40, 0, 30, 0))
	},

	/* ath.ko matches */
	{
		.desc = "ath world regdomain with 3 rules in ath/regd.o",
		.reg  = REG_MATCH("99", 3, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 0, 20, 0))
	}, {
		.desc = "ath world regdomain with 4 rules in ath/regd.o",
		.reg  = REG_MATCH("99", 4, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 0, 20, 0))
	}, {
		.desc = "ath world regdomain with 5 rules in ath/regd.o",
		.reg  = REG_MATCH("99", 5, NL80211_DFS_UNSET, REG_RULE(2402, 2472, 40, 0, 20, 0))
	}
};


struct search_insn {
	const char *desc;
	const uint16_t machine;
	const uint32_t search;
	const uint32_t replace;
	const uint32_t mask;
	int step;
};

static const struct search_insn search_insns[] = {
	/* radar frequency check */
	{
		.desc    = "ath_is_radar_freq() MIPS opcode in ath/regd.o",
		.machine = 0x0008,     /* MIPS */
		.search  = 0x2400eb74, /* addiu rX, rY, -5260 */
		.replace = 0x24000000, /* addiu rX, rY, 0	*/
		.mask    = 0xfc00ffff,
		.step    = 4
	},
	{
		.desc    = "ath_is_radar_freq() PPC opcode in ath/regd.o",
		.machine = 0x0014,     /* PPC */
		.search  = 0x3800eb74, /* addi rX, rY, -5260 */
		.replace = 0x38000000, /* addi rX, rY, 0 */
		.mask    = 0xfc00ffff,
		.step    = 4
	},
	{
		.desc    = "ath_is_radar_freq() x86 opcode in ath/regd.o (1/2)",
		.machine = 0x0003,	/* x86 */
		.search  = 0x0000148c,	/* 5260 */
		.replace = 0x00000000,  /* 0 */
		.mask    = 0x0000ffff,
		.step    = 1
	},
	{
		.desc    = "ath_is_radar_freq() x86 opcode in ath/regd.o (2/2)",
		.machine = 0x0003,	/* x86 */
		.search  = 0xffffeb74,	/* -5260 */
		.replace = 0x00000000,  /* 0 */
		.mask    = 0xffffffff,
		.step    = 1
	},
	{
		.desc    = "ath_is_radar_freq() x86-64 opcode in ath/regd.o (1/2)",
		.machine = 0x003e,	/* x86-64 */
		.search  = 0x0000148c,	/* 5260 */
		.replace = 0x00000000,  /* 0 */
		.mask    = 0x0000ffff,
		.step    = 1
	},
	{
		.desc    = "ath_is_radar_freq() x86-64 opcode in ath/regd.o (2/2)",
		.machine = 0x003e,	/* x86-64 */
		.search  = 0xffffeb74,	/* -5260 */
		.replace = 0x00000000,  /* 0 */
		.mask    = 0xffffffff,
		.step    = 1
	}
};


static void check_endianess(unsigned char *elf_hdr)
{
	int self_is_be = (htonl(42) == 42);
	int elf_is_be  = (elf_hdr[5] == 2);

	if (self_is_be != elf_is_be)
	{
		need_byteswap = 1;
		printf("Byte swapping needed (utility %s endian, module %s endian)\n",
			   self_is_be ? "big" : "low",
			   elf_is_be  ? "big" : "low");
	}
}

static void bswap_rule(struct ieee80211_reg_rule *r)
{
	r->freq_range.start_freq_khz    = bswap_32(r->freq_range.start_freq_khz);
	r->freq_range.end_freq_khz      = bswap_32(r->freq_range.end_freq_khz);
	r->freq_range.max_bandwidth_khz = bswap_32(r->freq_range.max_bandwidth_khz);

	r->power_rule.max_antenna_gain  = bswap_32(r->power_rule.max_antenna_gain);
	r->power_rule.max_eirp          = bswap_32(r->power_rule.max_eirp);

	r->flags                        = bswap_32(r->flags);
}

static int patch_regdomain(struct ieee80211_regdomain *pos,
                           const struct ieee80211_regdomain *comp)
{
	struct ieee80211_reg_rule r2 = REG_RULE(2400, 2483, 40, 0, 30, 0);
	struct ieee80211_reg_rule r5 = REG_RULE(5140, 5860, 160, 0, 30, 0);
	struct ieee80211_regdomain pattern = *comp;

	if (need_byteswap)
	{
		bswap_rule(&pattern.reg_rules[0]);
		pattern.dfs_region = bswap_32(pattern.dfs_region);
		pattern.n_reg_rules = bswap_32(pattern.n_reg_rules);
	}

	if (!memcmp(pos, &pattern, sizeof(pattern)))
	{
		pos->reg_rules[0] = r2;
		pos->reg_rules[1] = r5;
		pos->n_reg_rules = 2;
		pos->dfs_region = 0;

		if (need_byteswap)
		{
			bswap_rule(&pos->reg_rules[0]);
			bswap_rule(&pos->reg_rules[1]);
			pos->n_reg_rules = bswap_32(pos->n_reg_rules);
		}

		return 0;
	}

	return 1;
}


static uint16_t check_ath_ko(unsigned char *elf_hdr, const char *filename)
{
	uint16_t type = *(uint16_t *)(elf_hdr + 18);
	const char *file = strrchr(filename, '/');

	if (!file)
		file = filename;
	else
		file++;

	if (need_byteswap)
		type = bswap_16(type);

	if (!strcmp(file, "ath.ko"))
		return type;

	return 0;
}

static int patch_insn(uint32_t *pos, const struct search_insn *insn)
{
	uint32_t cmp = need_byteswap ? bswap_32(*pos) : *pos;

	if ((cmp & insn->mask) == insn->search)
	{
		*pos = need_byteswap ? bswap_32(insn->replace | (cmp & ~insn->mask))
		                     : insn->replace | (cmp & ~insn->mask);

		return 0;
	}

	return 1;
}


static int tryopen(const char *path, int *size, void **map)
{
	int fd;
	struct stat s;

	if (stat(path, &s))
	{
		perror("stat()");
		return -1;
	}

	if ((fd = open(path, O_RDWR)) == -1)
	{
		perror("open()");
		return -2;
	}

	*size = s.st_size;
	*map = mmap(NULL, *size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (*map == MAP_FAILED)
	{
		close(fd);
		perror("mmap()");
		return -3;
	}

	return fd;
}

int main(int argc, char **argv)
{
	int i, j, fd, sz;
	int found = 0;
	uint16_t ath_ko_machine = 0;

	void *map;
	char *tmp = NULL, cmd[PATH_MAX * 2 + 4];

	if (argc < 2)
	{
		printf("Usage: %s module.ko\n", argv[0]);
		exit(1);
	}

	fd = tryopen(argv[1], &sz, &map);

	if (fd == -3)
	{
		printf("Memory mapping failed (missing fs support?), retrying from tmpfs\n");

		tmp = tmpnam(NULL);

		sprintf(cmd, "cp %s %s", argv[1], tmp);
		system(cmd);

		fd = tryopen(tmp, &sz, &map);
	}

	if (fd < 0)
	{
		if (tmp)
			unlink(tmp);

		exit(1);
	}

	check_endianess(map);
	ath_ko_machine = check_ath_ko(map, argv[1]);

	if (ath_ko_machine)
	{
		for (j = 0; j < sizeof(search_insns)/sizeof(search_insns[0]); j++)
		{
			if (search_insns[j].machine != ath_ko_machine)
				continue;

			for (i = 0; i < (sz - sizeof(search_regdomains[0].reg)); i += search_insns[j].step)
			{
				if (!patch_insn(map + i, &search_insns[j]))
				{
					printf("Patching @ 0x%08x: %s\n", i, search_insns[j].desc);
					found = 1;
				}
			}
		}
	}

	for (i = 0; i < (sz - sizeof(search_regdomains[0].reg)); i += sizeof(uint32_t))
	{
		for (j = 0; j < (sizeof(search_regdomains)/sizeof(search_regdomains[0])); j++)
		{
			if (!patch_regdomain(map + i, &search_regdomains[j].reg))
			{
				printf("Patching @ 0x%08x: %s\n", i, search_regdomains[j].desc);
				found = 1;
			}
		}
	}

	if (munmap(map, sz))
	{
		perror("munmap()");
		exit(1);
	}

	if (tmp)
	{
		if (found)
		{
			sprintf(cmd, "cp %s %s", tmp, argv[1]);
			system(cmd);
		}

		unlink(tmp);
	}

	close(fd);

	if (!found)
	{
		printf("Unable to find regulatory rules (already patched?)\n");
		exit(1);
	}

	return 0;
}
