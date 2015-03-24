#define _BSD_SOURCE
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <inttypes.h>

typedef int8_t s8;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint64_t u64;

/* taken from ath9k.h */
#define SPECTRAL_HT20_NUM_BINS          56

enum ath_fft_sample_type {
	ATH_FFT_SAMPLE_HT20 = 1
};

struct fft_sample_tlv {
	u8 type; /* see ath_fft_sample */
	u16 length;
	/* type dependent data follows */
} __attribute__((packed));

struct fft_sample_ht20 {
	u8 max_exp;

	u16 freq;
	s8 rssi;
	s8 noise;

	u16 max_magnitude;
	u8 max_index;
	u8 bitmap_weight;

	u64 tsf;

	u8 data[SPECTRAL_HT20_NUM_BINS];
} __attribute__((packed));

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


static void parse_ht20(void) {
	struct fft_sample_ht20 sample;
	int i, data, datasquaresum = 0;
	float signal, freq;

	memset(&sample, 0, sizeof(sample));
	if (fread(&sample, sizeof(sample), 1, stdin) != 1) {
		fprintf(stderr, "error: incomplete read in %s\n", __func__);
		return;
	}

	sample.freq = be16toh(sample.freq);
	sample.max_magnitude = be16toh(sample.max_magnitude);
	sample.tsf = be64toh(sample.tsf);

	/* The following has been taken from FFT_eval by Simon Wunderlich */

	for (i=0; i<ARRAY_SIZE(sample.data); i++) {
		data = sample.data[i] << sample.max_exp;
		data *= data;
		datasquaresum += data;
	}

	for (i=0; i<sizeof(sample.data)/sizeof(sample.data[0]); i++) {
		data = sample.data[i] << sample.max_exp;
		if (data == 0)
			data = 1;
		signal = sample.noise + sample.rssi + 20 * log10f(data) - log10f(datasquaresum) * 10;
		freq = sample.freq - 10 + (20*i/ARRAY_SIZE(sample.data));
		printf("center-freq %d freq %f signal %f\n", sample.freq, freq, signal);
	}
}

int main() {
	struct fft_sample_tlv tlv;
	u8 discard;

	while (!feof(stdin)) {
		if (fread(&tlv.type, 1, 1, stdin) != 1)
			break;
		if (fread(&tlv.length, 2, 1, stdin) != 1)
			break;

		switch (tlv.type) {
		case ATH_FFT_SAMPLE_HT20:
			parse_ht20();
			break;
		default:
			fprintf(stderr, "unsupported TLV type = %hhu\n", tlv.type);
			for (; tlv.length > 0; tlv.length--)
				fread(&discard, 1, 1, stdin);
			break;
		}
	}

	return 0;
}
