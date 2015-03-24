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

#include <sys/types.h>

#define HAL_MODE_11A_TURBO  HAL_MODE_108A
#define HAL_MODE_11G_TURBO  HAL_MODE_108G

/*
 * Used to set the RegDomain bitmask which chooses which frequency
 * band specs are used.
 */

#define YES 1
#define NO  0

/* This is from ah_eeprom.h */
#define SD_NO_CTL               0xE0
#define NO_CTL                  0xff
#define CTL_MODE_M              7
#define CTL_11A                 0
#define CTL_11B                 1
#define CTL_11G                 2
#define CTL_TURBO               3
#define CTL_108G                4
#define CTL_2GHT20              5
#define CTL_5GHT20              6
#define CTL_2GHT40              7
#define CTL_5GHT40              8

/* This is from ah_eeprom.h */

/* regulatory capabilities */
#define AR_EEPROM_EEREGCAP_EN_FCC_MIDBAND   0x0040
#define AR_EEPROM_EEREGCAP_EN_KK_U1_EVEN    0x0080
#define AR_EEPROM_EEREGCAP_EN_KK_U2             0x0100
#define AR_EEPROM_EEREGCAP_EN_KK_MIDBAND    0x0200
#define AR_EEPROM_EEREGCAP_EN_KK_U1_ODD     0x0400
#define AR_EEPROM_EEREGCAP_EN_KK_NEW_11A    0x0800

/* This is from ah.h */
/* channelFlags */
#define CHANNEL_CW_INT    0x00002 /* CW interference detected on channel */
#define CHANNEL_TURBO     0x00010 /* Turbo Channel */
#define CHANNEL_CCK       0x00020 /* CCK channel */
#define CHANNEL_OFDM      0x00040 /* OFDM channel */
#define CHANNEL_2GHZ      0x00080 /* 2 GHz spectrum channel. */
#define CHANNEL_5GHZ      0x00100 /* 5 GHz spectrum channel */
#define CHANNEL_PASSIVE   0x00200 /* Only passive scan allowed in the channel */
#define CHANNEL_DYN       0x00400 /* dynamic CCK-OFDM channel */
#define CHANNEL_XR        0x00800 /* XR channel */
#define CHANNEL_STURBO    0x02000 /* Static turbo, no 11a-only usage */
#define CHANNEL_HALF      0x04000 /* Half rate channel */
#define CHANNEL_QUARTER   0x08000 /* Quarter rate channel */
#define CHANNEL_HT20      0x10000 /* HT20 channel */
#define CHANNEL_HT40PLUS  0x20000 /* HT40 channel with extention channel above */
#define CHANNEL_HT40MINUS 0x40000 /* HT40 channel with extention channel below */

#define CHANNEL_A           (CHANNEL_5GHZ|CHANNEL_OFDM)
#define CHANNEL_B           (CHANNEL_2GHZ|CHANNEL_CCK)
#define CHANNEL_PUREG       (CHANNEL_2GHZ|CHANNEL_OFDM)
#ifdef notdef
#define CHANNEL_G           (CHANNEL_2GHZ|CHANNEL_DYN)
#else
#define CHANNEL_G           (CHANNEL_2GHZ|CHANNEL_OFDM)
#endif
#define CHANNEL_T           (CHANNEL_5GHZ|CHANNEL_OFDM|CHANNEL_TURBO)
#define CHANNEL_ST          (CHANNEL_T|CHANNEL_STURBO)
#define CHANNEL_108G        (CHANNEL_2GHZ|CHANNEL_OFDM|CHANNEL_TURBO)
#define CHANNEL_108A        CHANNEL_T
#define CHANNEL_X           (CHANNEL_5GHZ|CHANNEL_OFDM|CHANNEL_XR)
#define CHANNEL_G_HT20      (CHANNEL_2GHZ|CHANNEL_HT20)
#define CHANNEL_A_HT20      (CHANNEL_5GHZ|CHANNEL_HT20)
#define CHANNEL_G_HT40PLUS  (CHANNEL_2GHZ|CHANNEL_HT40PLUS)
#define CHANNEL_G_HT40MINUS (CHANNEL_2GHZ|CHANNEL_HT40MINUS)
#define CHANNEL_A_HT40PLUS  (CHANNEL_5GHZ|CHANNEL_HT40PLUS)
#define CHANNEL_A_HT40MINUS (CHANNEL_5GHZ|CHANNEL_HT40MINUS)
#define CHANNEL_ALL \
	        (CHANNEL_OFDM|CHANNEL_CCK| CHANNEL_2GHZ | CHANNEL_5GHZ | CHANNEL_TURBO | CHANNEL_HT20 | CHANNEL_HT40PLUS | CHANNEL_HT40MINUS)
#define CHANNEL_ALL_NOTURBO (CHANNEL_ALL &~ CHANNEL_TURBO)


#define BMLEN 2     /* Use 2 64 bit uint for channel bitmask
               NB: Must agree with macro below (BM) */
#define BMZERO {(u_int64_t) 0, (u_int64_t) 0}   /* BMLEN zeros */

#define BM(_fa, _fb, _fc, _fd, _fe, _ff, _fg, _fh, _fi, _fj, _fk, _fl) \
      {((((_fa >= 0) && (_fa < 64)) ? (((u_int64_t) 1) << _fa) : (u_int64_t) 0) | \
    (((_fb >= 0) && (_fb < 64)) ? (((u_int64_t) 1) << _fb) : (u_int64_t) 0) | \
    (((_fc >= 0) && (_fc < 64)) ? (((u_int64_t) 1) << _fc) : (u_int64_t) 0) | \
    (((_fd >= 0) && (_fd < 64)) ? (((u_int64_t) 1) << _fd) : (u_int64_t) 0) | \
    (((_fe >= 0) && (_fe < 64)) ? (((u_int64_t) 1) << _fe) : (u_int64_t) 0) | \
    (((_ff >= 0) && (_ff < 64)) ? (((u_int64_t) 1) << _ff) : (u_int64_t) 0) | \
    (((_fg >= 0) && (_fg < 64)) ? (((u_int64_t) 1) << _fg) : (u_int64_t) 0) | \
    (((_fh >= 0) && (_fh < 64)) ? (((u_int64_t) 1) << _fh) : (u_int64_t) 0) | \
    (((_fi >= 0) && (_fi < 64)) ? (((u_int64_t) 1) << _fi) : (u_int64_t) 0) | \
    (((_fj >= 0) && (_fj < 64)) ? (((u_int64_t) 1) << _fj) : (u_int64_t) 0) | \
    (((_fk >= 0) && (_fk < 64)) ? (((u_int64_t) 1) << _fk) : (u_int64_t) 0) | \
    (((_fl >= 0) && (_fl < 64)) ? (((u_int64_t) 1) << _fl) : (u_int64_t) 0) | \
           ((((_fa > 63) && (_fa < 128)) ? (((u_int64_t) 1) << (_fa - 64)) : (u_int64_t) 0) | \
        (((_fb > 63) && (_fb < 128)) ? (((u_int64_t) 1) << (_fb - 64)) : (u_int64_t) 0) | \
        (((_fc > 63) && (_fc < 128)) ? (((u_int64_t) 1) << (_fc - 64)) : (u_int64_t) 0) | \
        (((_fd > 63) && (_fd < 128)) ? (((u_int64_t) 1) << (_fd - 64)) : (u_int64_t) 0) | \
        (((_fe > 63) && (_fe < 128)) ? (((u_int64_t) 1) << (_fe - 64)) : (u_int64_t) 0) | \
        (((_ff > 63) && (_ff < 128)) ? (((u_int64_t) 1) << (_ff - 64)) : (u_int64_t) 0) | \
        (((_fg > 63) && (_fg < 128)) ? (((u_int64_t) 1) << (_fg - 64)) : (u_int64_t) 0) | \
        (((_fh > 63) && (_fh < 128)) ? (((u_int64_t) 1) << (_fh - 64)) : (u_int64_t) 0) | \
        (((_fi > 63) && (_fi < 128)) ? (((u_int64_t) 1) << (_fi - 64)) : (u_int64_t) 0) | \
        (((_fj > 63) && (_fj < 128)) ? (((u_int64_t) 1) << (_fj - 64)) : (u_int64_t) 0) | \
        (((_fk > 63) && (_fk < 128)) ? (((u_int64_t) 1) << (_fk - 64)) : (u_int64_t) 0) | \
        (((_fl > 63) && (_fl < 128)) ? (((u_int64_t) 1) << (_fl - 64)) : (u_int64_t) 0)))}

/*
 * The following table is the master list for all different freqeuncy
 * bands with the complete matrix of all possible flags and settings
 * for each band if it is used in ANY reg domain.
 */

#define DEF_REGDMN      FCC1_FCCA
#define DEF_DMN_5       FCC1
#define DEF_DMN_2       FCCA
#define COUNTRY_ERD_FLAG        0x8000
#define WORLDWIDE_ROAMING_FLAG  0x4000
#define SUPER_DOMAIN_MASK   0x0fff
#define COUNTRY_CODE_MASK   0x3fff
#define CF_INTERFERENCE     (CHANNEL_CW_INT | CHANNEL_RADAR_INT)
#define CHANNEL_14      (2484)  /* 802.11g operation is not permitted on channel 14 */
#define IS_11G_CH14(_ch,_cf) \
    (((_ch) == CHANNEL_14) && ((_cf) == CHANNEL_G))

/*
 * The following describe the bit masks for different passive scan
 * capability/requirements per regdomain.
 */
#define NO_PSCAN    0x0ULL
#define PSCAN_FCC   0x0000000000000001ULL
#define PSCAN_FCC_T 0x0000000000000002ULL
#define PSCAN_ETSI  0x0000000000000004ULL
#define PSCAN_MKK1  0x0000000000000008ULL
#define PSCAN_MKK2  0x0000000000000010ULL
#define PSCAN_MKKA  0x0000000000000020ULL
#define PSCAN_MKKA_G    0x0000000000000040ULL
#define PSCAN_ETSIA 0x0000000000000080ULL
#define PSCAN_ETSIB 0x0000000000000100ULL
#define PSCAN_ETSIC 0x0000000000000200ULL
#define PSCAN_WWR   0x0000000000000400ULL
#define PSCAN_MKKA1 0x0000000000000800ULL
#define PSCAN_MKKA1_G   0x0000000000001000ULL
#define PSCAN_MKKA2 0x0000000000002000ULL
#define PSCAN_MKKA2_G   0x0000000000004000ULL
#define PSCAN_MKK3  0x0000000000008000ULL
#define PSCAN_DEFER 0x7FFFFFFFFFFFFFFFULL
#define IS_ECM_CHAN 0x8000000000000000ULL

/* Old macros from ah_regdomain.c */
#define	array_size(a)	(sizeof (a) / sizeof (a[0]))

/* 10MHz is half the 11A bandwidth used to determine upper edge freq
   of the outdoor channel */
#define HALF_MAXCHANBW		10

/* Mask to check whether a domain is a multidomain or a single
   domain */

#define MULTI_DOMAIN_MASK 0xFF00

#define	WORLD_SKU_MASK		0x00F0
#define	WORLD_SKU_PREFIX	0x0060

#define IS_HT40_MODE(_mode)      \
                    (((_mode == HAL_MODE_11NA_HT40PLUS  || \
                     _mode == HAL_MODE_11NG_HT40PLUS    || \
                     _mode == HAL_MODE_11NA_HT40MINUS   || \
                     _mode == HAL_MODE_11NG_HT40MINUS) ? 1 : 0))

#define CHANNEL_HALF_BW		10
#define CHANNEL_QUARTER_BW	5

/* These are from ah.h */
enum {
	HAL_MODE_11A              = 0x00001,      /* 11a channels */
	HAL_MODE_TURBO            = 0x00002,      /* 11a turbo-only channels */
	HAL_MODE_11B              = 0x00004,      /* 11b channels */
	HAL_MODE_PUREG            = 0x00008,      /* 11g channels (OFDM only) */
#ifdef notdef                 
	HAL_MODE_11G              = 0x00010,      /* 11g channels (OFDM/CCK) */
#else
	HAL_MODE_11G              = 0x00008,      /* XXX historical */
#endif
	HAL_MODE_108G             = 0x00020,      /* 11a+Turbo channels */
	HAL_MODE_108A             = 0x00040,      /* 11g+Turbo channels */
	HAL_MODE_XR               = 0x00100,      /* XR channels */
	HAL_MODE_11A_HALF_RATE    = 0x00200,      /* 11A half rate channels */
	HAL_MODE_11A_QUARTER_RATE = 0x00400,      /* 11A quarter rate channels */
	HAL_MODE_11NG_HT20        = 0x00800,      /* 11N-G HT20 channels */
	HAL_MODE_11NA_HT20        = 0x01000,      /* 11N-A HT20 channels */
	HAL_MODE_11NG_HT40PLUS    = 0x02000,      /* 11N-G HT40 + channels */
	HAL_MODE_11NG_HT40MINUS   = 0x04000,      /* 11N-G HT40 - channels */
	HAL_MODE_11NA_HT40PLUS    = 0x08000,      /* 11N-A HT40 + channels */
	HAL_MODE_11NA_HT40MINUS   = 0x10000,      /* 11N-A HT40 - channels */
	HAL_MODE_ALL              = 0xffffffff
};


/*
 * THE following table is the mapping of regdomain pairs specified by
 * an 8 bit regdomain value to the individual unitary reg domains
 */

struct reg_dmn_pair_mapping {
    u_int16_t regDmnEnum;  /* 16 bit reg domain pair */
    u_int16_t regDmn5GHz;  /* 5GHz reg domain */
    u_int16_t regDmn2GHz;  /* 2GHz reg domain */
    u_int32_t flags5GHz;        /* Requirements flags (AdHoc
                       disallow, noise floor cal needed,
                       etc) */
    u_int32_t flags2GHz;        /* Requirements flags (AdHoc
                       disallow, noise floor cal needed,
                       etc) */
    u_int64_t pscanMask;        /* Passive Scan flags which
                       can override unitary domain
                       passive scan flags.  This
                       value is used as a mask on
                       the unitary flags*/
    u_int16_t singleCC;     /* Country code of single country if
                       a one-on-one mapping exists */
};

/*
 * The following table of vendor specific regdomain pairs and
 * additional flags used to modify the flags5GHz and flags2GHz
 * of the original regdomain
 */

struct ccmap {
    char isoName[3];
    u_int16_t countryCode;
};

struct country_code_to_enum_rd {
    u_int16_t	countryCode;
    u_int16_t      regDmnEnum;
    const char*     isoName;
    const char*     name;
    u_int8_t        allow11g;
    u_int8_t        allow11aTurbo;
    u_int8_t        allow11gTurbo;
        u_int8_t                allow11ng20;    /* HT-20 allowed in 2GHz? */
        u_int8_t                allow11ng40;    /* HT-40 allowed in 2GHz? */
        u_int8_t                allow11na20;    /* HT-20 allowed in 5GHz? */
        u_int8_t                allow11na40;    /* HT-40 allowed in 5GHz? */
    u_int16_t       outdoorChanStart;
};

struct reg_dmn_freq_band {
    u_int16_t   lowChannel; /* Low channel center in MHz */
    u_int16_t   highChannel;    /* High Channel center in MHz */
    u_int8_t    powerDfs;   /* Max power (dBm) for channel
                       range when using DFS */
    u_int8_t    antennaMax; /* Max allowed antenna gain */
    u_int8_t    channelBW;  /* Bandwidth of the channel */
    u_int8_t    channelSep; /* Channel separation within
                       the band */
    u_int64_t   useDfs;     /* Use DFS in the RegDomain
                       if corresponding bit is set */
    u_int64_t   usePassScan;    /* Use Passive Scan in the RegDomain
                       if corresponding bit is set */
    u_int8_t    regClassId; /* Regulatory class id */
};

struct reg_domain {
    u_int16_t regDmnEnum;   /* value from EnumRd table */
    u_int8_t conformanceTestLimit;
    u_int64_t dfsMask;  /* DFS bitmask for 5Ghz tables */
    u_int64_t pscan;    /* Bitmask for passive scan */
    u_int32_t flags;    /* Requirement flags (AdHoc disallow, noise
                   floor cal needed, etc) */
    u_int64_t chan11a[BMLEN];/* 128 bit bitmask for channel/band
                   selection */
    u_int64_t chan11a_turbo[BMLEN];/* 128 bit bitmask for channel/band
                   selection */
    u_int64_t chan11a_dyn_turbo[BMLEN]; /* 128 bit bitmask for channel/band
                           selection */
    u_int64_t chan11b[BMLEN];/* 128 bit bitmask for channel/band
                   selection */
    u_int64_t chan11g[BMLEN];/* 128 bit bitmask for channel/band
                   selection */
    u_int64_t chan11g_turbo[BMLEN];/* 128 bit bitmask for channel/band
                      selection */
};

struct cmode {
    u_int32_t   mode;
    u_int32_t   flags;
};

/* check rd flags in eeprom for japan */
struct japan_bandcheck {
    u_int16_t       freqbandbit;
    u_int32_t       eepromflagtocheck;
};

/* Common mode power table for 5Ghz */
struct common_mode_power {
    u_int16_t lchan;
    u_int16_t hchan;
    u_int8_t  pwrlvl;
};

/* From ah.h */
#define	CTRY_DEBUG	0x1ff	/* debug country code */
#define	CTRY_DEFAULT	 0	/* default country code */

/*
 * Country/Region Codes from MS WINNLS.H
 * Numbering from ISO 3166
 */
enum CountryCode {
    CTRY_ALBANIA              = 8,       /* Albania */
    CTRY_ALGERIA              = 12,      /* Algeria */
    CTRY_ARGENTINA            = 32,      /* Argentina */
    CTRY_ARMENIA              = 51,      /* Armenia */
    CTRY_AUSTRALIA            = 36,      /* Australia */
    CTRY_AUSTRIA              = 40,      /* Austria */
    CTRY_AZERBAIJAN           = 31,      /* Azerbaijan */
    CTRY_BAHRAIN              = 48,      /* Bahrain */
    CTRY_BELARUS              = 112,     /* Belarus */
    CTRY_BELGIUM              = 56,      /* Belgium */
    CTRY_BELIZE               = 84,      /* Belize */
    CTRY_BOLIVIA              = 68,      /* Bolivia */
    CTRY_BOSNIA_HERZ          = 70,      /* Bosnia and Herzegowina */
    CTRY_BRAZIL               = 76,      /* Brazil */
    CTRY_BRUNEI_DARUSSALAM    = 96,      /* Brunei Darussalam */
    CTRY_BULGARIA             = 100,     /* Bulgaria */
    CTRY_CANADA               = 124,     /* Canada */
    CTRY_CHILE                = 152,     /* Chile */
    CTRY_CHINA                = 156,     /* People's Republic of China */
    CTRY_COLOMBIA             = 170,     /* Colombia */
    CTRY_COSTA_RICA           = 188,     /* Costa Rica */
    CTRY_CROATIA              = 191,     /* Croatia */
    CTRY_CYPRUS               = 196,
    CTRY_CZECH                = 203,     /* Czech Republic */
    CTRY_DENMARK              = 208,     /* Denmark */
    CTRY_DOMINICAN_REPUBLIC   = 214,     /* Dominican Republic */
    CTRY_ECUADOR              = 218,     /* Ecuador */
    CTRY_EGYPT                = 818,     /* Egypt */
    CTRY_EL_SALVADOR          = 222,     /* El Salvador */
    CTRY_ESTONIA              = 233,     /* Estonia */
    CTRY_FAEROE_ISLANDS       = 234,     /* Faeroe Islands */
    CTRY_FINLAND              = 246,     /* Finland */
    CTRY_FRANCE               = 250,     /* France */
    CTRY_GEORGIA              = 268,     /* Georgia */
    CTRY_GERMANY              = 276,     /* Germany */
    CTRY_GREECE               = 300,     /* Greece */
    CTRY_GUATEMALA            = 320,     /* Guatemala */
    CTRY_HONDURAS             = 340,     /* Honduras */
    CTRY_HONG_KONG            = 344,     /* Hong Kong S.A.R., P.R.C. */
    CTRY_HUNGARY              = 348,     /* Hungary */
    CTRY_ICELAND              = 352,     /* Iceland */
    CTRY_INDIA                = 356,     /* India */
    CTRY_INDONESIA            = 360,     /* Indonesia */
    CTRY_IRAN                 = 364,     /* Iran */
    CTRY_IRAQ                 = 368,     /* Iraq */
    CTRY_IRELAND              = 372,     /* Ireland */
    CTRY_ISRAEL               = 376,     /* Israel */
    CTRY_ITALY                = 380,     /* Italy */
    CTRY_JAMAICA              = 388,     /* Jamaica */
    CTRY_JAPAN                = 392,     /* Japan */
    CTRY_JORDAN               = 400,     /* Jordan */
    CTRY_KAZAKHSTAN           = 398,     /* Kazakhstan */
    CTRY_KENYA                = 404,     /* Kenya */
    CTRY_KOREA_NORTH          = 408,     /* North Korea */
    CTRY_KOREA_ROC            = 410,     /* South Korea */
    CTRY_KOREA_ROC2           = 411,     /* South Korea */
    CTRY_KOREA_ROC3           = 412,     /* South Korea */
    CTRY_KUWAIT               = 414,     /* Kuwait */
    CTRY_LATVIA               = 428,     /* Latvia */
    CTRY_LEBANON              = 422,     /* Lebanon */
    CTRY_LIBYA                = 434,     /* Libya */
    CTRY_LIECHTENSTEIN        = 438,     /* Liechtenstein */
    CTRY_LITHUANIA            = 440,     /* Lithuania */
    CTRY_LUXEMBOURG           = 442,     /* Luxembourg */
    CTRY_MACAU                = 446,     /* Macau */
    CTRY_MACEDONIA            = 807,     /* the Former Yugoslav Republic of Macedonia */
    CTRY_MALAYSIA             = 458,     /* Malaysia */
    CTRY_MALTA                = 470,     /* Malta */
    CTRY_MEXICO               = 484,     /* Mexico */
    CTRY_MONACO               = 492,     /* Principality of Monaco */
    CTRY_MOROCCO              = 504,     /* Morocco */
	CTRY_NEPAL				  = 524,	 /* Nepal */
    CTRY_NETHERLANDS          = 528,     /* Netherlands */
	CTRY_NETHERLANDS_ANTILLES = 530,	 /* Netherlands-Antilles */
    CTRY_NEW_ZEALAND          = 554,     /* New Zealand */
    CTRY_NICARAGUA            = 558,     /* Nicaragua */
    CTRY_NORWAY               = 578,     /* Norway */
    CTRY_OMAN                 = 512,     /* Oman */
    CTRY_PAKISTAN             = 586,     /* Islamic Republic of Pakistan */
    CTRY_PANAMA               = 591,     /* Panama */
	CTRY_PAPUA_NEW_GUINEA	  = 598,	 /* Papua New Guinea */
    CTRY_PARAGUAY             = 600,     /* Paraguay */
    CTRY_PERU                 = 604,     /* Peru */
    CTRY_PHILIPPINES          = 608,     /* Republic of the Philippines */
    CTRY_POLAND               = 616,     /* Poland */
    CTRY_PORTUGAL             = 620,     /* Portugal */
    CTRY_PUERTO_RICO          = 630,     /* Puerto Rico */
    CTRY_QATAR                = 634,     /* Qatar */
    CTRY_ROMANIA              = 642,     /* Romania */
    CTRY_RUSSIA               = 643,     /* Russia */
    CTRY_SAUDI_ARABIA         = 682,     /* Saudi Arabia */
    CTRY_SERBIA_MONTENEGRO    = 891,     /* Serbia and Montenegro */
    CTRY_SINGAPORE            = 702,     /* Singapore */
    CTRY_SLOVAKIA             = 703,     /* Slovak Republic */
    CTRY_SLOVENIA             = 705,     /* Slovenia */
    CTRY_SOUTH_AFRICA         = 710,     /* South Africa */
    CTRY_SPAIN                = 724,     /* Spain */
	CTRY_SRI_LANKA			  = 144,	 /* Sri Lanka */
    CTRY_SWEDEN               = 752,     /* Sweden */
    CTRY_SWITZERLAND          = 756,     /* Switzerland */
    CTRY_SYRIA                = 760,     /* Syria */
    CTRY_TAIWAN               = 158,     /* Taiwan */
    CTRY_THAILAND             = 764,     /* Thailand */
    CTRY_TRINIDAD_Y_TOBAGO    = 780,     /* Trinidad y Tobago */
    CTRY_TUNISIA              = 788,     /* Tunisia */
    CTRY_TURKEY               = 792,     /* Turkey */
    CTRY_UAE                  = 784,     /* U.A.E. */
    CTRY_UKRAINE              = 804,     /* Ukraine */
    CTRY_UNITED_KINGDOM       = 826,     /* United Kingdom */
    CTRY_UNITED_STATES        = 840,     /* United States */
    CTRY_UNITED_STATES_FCC49  = 842,     /* United States (Public Safety)*/
    CTRY_URUGUAY              = 858,     /* Uruguay */
    CTRY_UZBEKISTAN           = 860,     /* Uzbekistan */
    CTRY_VENEZUELA            = 862,     /* Venezuela */
    CTRY_VIET_NAM             = 704,     /* Viet Nam */
    CTRY_YEMEN                = 887,     /* Yemen */
    CTRY_ZIMBABWE             = 716,     /* Zimbabwe */

	/*
	** Japan special codes.  Boy, do they have a lot
	*/

    CTRY_JAPAN1               = 393,     /* Japan (JP1) */
    CTRY_JAPAN2               = 394,     /* Japan (JP0) */
    CTRY_JAPAN3               = 395,     /* Japan (JP1-1) */
    CTRY_JAPAN4               = 396,     /* Japan (JE1) */
    CTRY_JAPAN5               = 397,     /* Japan (JE2) */
    CTRY_JAPAN6               = 4006,    /* Japan (JP6) */
    CTRY_JAPAN7            	  = 4007,    /* Japan (J7) */
    CTRY_JAPAN8           	  = 4008,    /* Japan (J8) */
    CTRY_JAPAN9           	  = 4009,    /* Japan (J9) */
    CTRY_JAPAN10          	  = 4010,    /* Japan (J10) */
    CTRY_JAPAN11          	  = 4011,    /* Japan (J11) */
    CTRY_JAPAN12          	  = 4012,    /* Japan (J12) */
    CTRY_JAPAN13          	  = 4013,    /* Japan (J13) */
    CTRY_JAPAN14          	  = 4014,    /* Japan (J14) */
    CTRY_JAPAN15          	  = 4015,    /* Japan (J15) */
    CTRY_JAPAN16              = 4016,    /* Japan (J16) */
    CTRY_JAPAN17              = 4017,    /* Japan (J17) */
    CTRY_JAPAN18              = 4018,    /* Japan (J18) */
    CTRY_JAPAN19              = 4019,    /* Japan (J19) */
    CTRY_JAPAN20              = 4020,    /* Japan (J20) */
    CTRY_JAPAN21              = 4021,    /* Japan (J21) */
    CTRY_JAPAN22              = 4022,    /* Japan (J22) */
    CTRY_JAPAN23              = 4023,    /* Japan (J23) */
    CTRY_JAPAN24              = 4024,    /* Japan (J24) */
    CTRY_JAPAN25              = 4025,    /* Japan (J25) */
    CTRY_JAPAN26              = 4026,    /* Japan (J26) */
    CTRY_JAPAN27              = 4027,    /* Japan (J27) */
    CTRY_JAPAN28              = 4028,    /* Japan (J28) */
    CTRY_JAPAN29              = 4029,    /* Japan (J29) */
    CTRY_JAPAN30              = 4030,    /* Japan (J30) */
    CTRY_JAPAN31              = 4031,    /* Japan (J31) */
    CTRY_JAPAN32              = 4032,    /* Japan (J32) */
    CTRY_JAPAN33              = 4033,    /* Japan (J33) */
    CTRY_JAPAN34              = 4034,    /* Japan (J34) */
    CTRY_JAPAN35              = 4035,    /* Japan (J35) */
    CTRY_JAPAN36              = 4036,    /* Japan (J36) */
    CTRY_JAPAN37              = 4037,    /* Japan (J37) */
    CTRY_JAPAN38              = 4038,    /* Japan (J38) */
    CTRY_JAPAN39              = 4039,    /* Japan (J39) */
    CTRY_JAPAN40              = 4040,    /* Japan (J40) */
    CTRY_JAPAN41              = 4041,    /* Japan (J41) */
    CTRY_JAPAN42              = 4042,    /* Japan (J42) */
    CTRY_JAPAN43              = 4043,    /* Japan (J43) */
    CTRY_JAPAN44              = 4044,    /* Japan (J44) */
    CTRY_JAPAN45              = 4045,    /* Japan (J45) */
    CTRY_JAPAN46              = 4046,    /* Japan (J46) */
    CTRY_JAPAN47              = 4047,    /* Japan (J47) */
    CTRY_JAPAN48              = 4048,    /* Japan (J48) */
    CTRY_JAPAN49              = 4049,    /* Japan (J49) */
    CTRY_JAPAN50              = 4050,    /* Japan (J50) */
    CTRY_JAPAN51              = 4051,    /* Japan (J51) */
    CTRY_JAPAN52              = 4052,    /* Japan (J52) */
    CTRY_JAPAN53              = 4053,    /* Japan (J53) */
    CTRY_JAPAN54              = 4054,    /* Japan (J54) */
    CTRY_JAPAN55              = 4055,    /* Japan (J55) */
    CTRY_JAPAN56              = 4056,    /* Japan (J56) */
    CTRY_JAPAN57              = 4057,    /* Japan (J57) */
    CTRY_JAPAN58              = 4058,    /* Japan (J58) */
    CTRY_JAPAN59              = 4059,    /* Japan (J59) */

	/*
	** "Special" codes for multiply defined countries, with the exception
	** of Japan and US.
	*/

    CTRY_AUSTRALIA2           = 5000,    /* Australia */
    CTRY_CANADA2              = 5001,    /* Canada */
	CTRY_BELGIUM2		      = 5002,	 /* Belgium implementation */	
	CTRY_WORLD		      = 8001	 /* World */	
};
