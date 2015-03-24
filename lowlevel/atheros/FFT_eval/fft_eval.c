/* 
 * Copyright (C) 2012 Simon Wunderlich <siwu@hrz.tu-chemnitz.de>
 * Copyright (C) 2012 Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 * 
 */

/*
 * This program has been created to aid open source spectrum
 * analyzer development for Qualcomm/Atheros AR92xx and AR93xx
 * based chipsets.
 */

#define _BSD_SOURCE
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <SDL/SDL.h>
#include <SDL/SDL_ttf.h>
#include <inttypes.h>

typedef int8_t s8;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint64_t u64;

enum ath_fft_sample_type {
        ATH_FFT_SAMPLE_HT20 = 1,
	ATH_FFT_SAMPLE_ATH10K = 3,
};

/*
 * ath9k spectral definition
 * TODO: HT40 still missing, any volunteers?
 */
#define SPECTRAL_HT20_NUM_BINS          56

struct fft_sample_tlv {
        u8 type;        /* see ath_fft_sample */
        u16 length;
        /* type dependent data follows */
} __attribute__((packed));

struct fft_sample_ht20 {
        struct fft_sample_tlv tlv;

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

/*
 * ath10k spectral sample definition
 */

#define SPECTRAL_ATH10K_MAX_NUM_BINS            256

struct fft_sample_ath10k {
	struct fft_sample_tlv tlv;
	u8 chan_width_mhz;
	uint16_t freq1;
	uint16_t freq2;
	int16_t noise;
	uint16_t max_magnitude;
	uint16_t total_gain_db;
	uint16_t base_pwr_db;
	uint64_t tsf;
	s8 max_index;
	u8 rssi;
	u8 relpwr_db;
	u8 avgpwr_db;
	u8 max_exp;

	u8 data[0];
} __attribute__((packed));


struct scanresult {
	union {
		struct fft_sample_tlv tlv;
		struct fft_sample_ht20 ht20;
		struct {
			struct fft_sample_ath10k header;
			u8 data[SPECTRAL_ATH10K_MAX_NUM_BINS];
		} ath10k;
	} sample;
	struct scanresult *next;
};

#define WIDTH	1600
#define HEIGHT	650
#define BPP	32

#define X_SCALE	10
#define Y_SCALE	4

#define	RMASK 	0x000000ff
#define RBITS	0
#define	GMASK	0x0000ff00
#define GBITS	8
#define	BMASK	0x00ff0000
#define	BBITS	16
#define	AMASK	0xff000000


SDL_Surface *screen = NULL;
TTF_Font *font = NULL;
struct scanresult *result_list;
int scanresults_n = 0;

int graphics_init_sdl(char *name)
{
	SDL_VideoInfo *VideoInfo;
	int SDLFlags;

	SDLFlags = SDL_HWPALETTE | SDL_RESIZABLE;

	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) < 0) {
		fprintf(stderr, "Initializing SDL failed\n");
		return -1;
	}
		
	if ((VideoInfo = (SDL_VideoInfo *) SDL_GetVideoInfo()) == NULL) {
		fprintf(stderr, "Getting SDL Video Info failed\n");
		return -1;
	}

	else {
		if (VideoInfo->hw_available) {
			SDLFlags |= SDL_HWSURFACE;
		} else {
			SDLFlags |= SDL_SWSURFACE;
		}
		if (VideoInfo->blit_hw)
			SDLFlags |= SDL_HWACCEL;
	}

	SDL_WM_SetCaption(name, name);
	screen = SDL_SetVideoMode(WIDTH, HEIGHT, BPP, SDLFlags);

	if (TTF_Init() < 0) {
		fprintf(stderr, "Initializing SDL TTF failed\n");
		return -1;
	}

	font = TTF_OpenFont("font/LiberationSans-Regular.ttf", 14);
	if (!font) {
		fprintf(stderr, "Opening font failed\n");
		return -1;
	}

	return 0;
}

void graphics_quit_sdl(void)
{
	SDL_Quit();
}

int pixel(Uint32 *pixels, int x, int y, Uint32 color)
{
	if (x < 0 || x >= WIDTH)
		return -1;
	if (y < 0 || y >= HEIGHT)
		return -1;

	pixels[x + y * WIDTH] |= color;
	return 0;
}


#define SIZE 3
/* this function blends a 2*SIZE x 2*SIZE blob at the given position with
 * the defined opacity. */
int bigpixel(Uint32 *pixels, int x, int y, Uint32 color, uint8_t opacity)
{
	int x1, y1;

	if (x - SIZE < 0 || x + SIZE >= WIDTH)
		return -1;
	if (y - SIZE < 0 || y + SIZE >= HEIGHT)
		return -1;

	for (x1 = x - SIZE; x1 < x + SIZE; x1++)
	for (y1 = y - SIZE; y1 < y + SIZE; y1++) {
		Uint32 r, g, b;

		r = ((pixels[x1 + y1 * WIDTH] & RMASK) >> RBITS) + ((((color & RMASK) >> RBITS) * opacity) / 255);
		if (r > 255) r = 255;
		g = ((pixels[x1 + y1 * WIDTH] & GMASK) >> GBITS) + ((((color & GMASK) >> GBITS) * opacity) / 255);
		if (g > 255) g = 255;
		b = ((pixels[x1 + y1 * WIDTH] & BMASK) >> BBITS) + ((((color & BMASK) >> BBITS) * opacity) / 255);
		if (b > 255) b = 255;

		pixels[x1 + y1 * WIDTH] = r << RBITS | g << GBITS | b << BBITS | (color & AMASK);
	}
	return 0;
}

int render_text(SDL_Surface *surface, char *text, int x, int y)
{
	SDL_Surface *text_surface;
	SDL_Color fontcolor = {255, 255, 255, 255};
	SDL_Rect fontdest = {0, 0, 0, 0};

	fontdest.x = x;
	fontdest.y = y;

	text_surface = TTF_RenderText_Solid(font, text, fontcolor);
	if (!text_surface)
		return -1;

	SDL_BlitSurface(text_surface, NULL, surface, &fontdest);
	SDL_FreeSurface(text_surface);

	return 0;
}


int plot_datapoint(Uint32 *pixels, float freq, float startfreq, int noise, int rssi, int data, int datasquaresum, int highlight)
{
	Uint32 color, opacity;
	int x, y;
	float signal;

	/* This is where the "magic" happens: interpret the signal
	 * to output some kind of data which looks useful.  */

	x = (X_SCALE * (freq - startfreq));
	if (data == 0)
		data = 1;
	signal = noise + rssi + 20 * log10f(data) - log10f(datasquaresum) * 10;

	y = 400 - (400.0 + Y_SCALE * signal);

	if (highlight) {
		color = RMASK | AMASK;
		opacity = 255;
	} else {
		color = BMASK | AMASK;
		opacity = 30;
	}

	if (bigpixel(pixels, x, y, color, opacity) < 0)
		return -1;
	return 0;
}


int draw_sample_ht20(Uint32 *pixels, struct scanresult *result, float startfreq, int highlight)
{
	int datamax = 0, datamin = 65536;
	int datasquaresum = 0;
	int i;

	for (i = 0; i < SPECTRAL_HT20_NUM_BINS; i++) {
		int data;

		data = (result->sample.ht20.data[i] << result->sample.ht20.max_exp);
		data *= data;
		datasquaresum += data;
		if (data > datamax) datamax = data;
		if (data < datamin) datamin = data;
	}

	if (highlight) {
		/* prints some statistical data about the currently selected
		 * data sample and auxiliary data. */
		printf("result: freq %04d rssi %03d, noise %03d, max_magnitude %04d max_index %03d bitmap_weight %03d tsf %"PRIu64" | ",
			result->sample.ht20.freq, result->sample.ht20.rssi, result->sample.ht20.noise,
			result->sample.ht20.max_magnitude, result->sample.ht20.max_index, result->sample.ht20.bitmap_weight,
			result->sample.ht20.tsf);
		printf("datamax = %d, datamin = %d, datasquaresum = %d\n", datamax, datamin, datasquaresum);
	}

	for (i = 0; i < SPECTRAL_HT20_NUM_BINS; i++) {
		float freq;
		int data;
		/*
		 * According to Dave Aragon from University of Washington,
		 * formerly Trapeze/Juniper Networks, in 2.4 GHz it should
		 * divide 22 MHz channel width into 64 subcarriers but
		 * only report the middle 56 subcarriers.
		 *
		 * For 5 GHz we do not know (Atheros claims it does not support
		 * this frequency band, but it works).
		 *
		 * Since all these calculations map pretty much to -10/+10 MHz,
		 * and we don't know better, use this assumption as well in 5 GHz.
		 */
		freq = result->sample.ht20.freq -
				(22.0 * SPECTRAL_HT20_NUM_BINS / 64.0) / 2 +
				(22.0 * (i + 0.5) / 64.0);

		data = result->sample.ht20.data[i] << result->sample.ht20.max_exp;
		plot_datapoint(pixels, freq, startfreq, result->sample.ht20.noise,
			       result->sample.ht20.rssi, data, datasquaresum,
			       highlight);
	}

	return 0;
}

static uint8_t get_max_exp(int8_t max_index, uint16_t max_magnitude, int bins, uint8_t *data)
{
	int dc_pos;
	u8 max_exp;

	dc_pos = bins / 2;
	/* peak index outside of bins */
	if (dc_pos < max_index || -dc_pos >= max_index)
		return 0;

	for (max_exp = 0; max_exp < 8; max_exp++) {
		if (data[dc_pos + max_index] == (max_magnitude >> max_exp))
			break;
	}

	/* max_exp not found */
	if (data[dc_pos + max_index] != (max_magnitude >> max_exp))
		return 0;

	return max_exp;
}

int draw_sample_ath10k(Uint32 *pixels, struct scanresult *result, float startfreq, int highlight)
{
	int datamax = 0, datamin = 65536;
	int datasquaresum = 0;
	int i, bins;

	bins = result->sample.tlv.length -
	       (sizeof(result->sample.ath10k.header) -
		sizeof(result->sample.ath10k.header.tlv));


	for (i = 0; i < bins; i++) {
		int data;

		data = (result->sample.ath10k.data[i] << result->sample.ath10k.header.max_exp);
		data *= data;
		datasquaresum += data;
		if (data > datamax) datamax = data;
		if (data < datamin) datamin = data;
	}

	if (highlight) {
		/* prints some statistical data about the currently selected
		 * data sample and auxiliary data. */
		printf("result: freq %04d/%04d (width %d MHz), %d bins, rssi %03d, noise %03d, max_magnitude %04d max_index %03d tsf %"PRIu64" | ",
		       result->sample.ath10k.header.freq1, result->sample.ath10k.header.freq1,
		       result->sample.ath10k.header.chan_width_mhz,
		       bins, result->sample.ath10k.header.rssi,
		       result->sample.ath10k.header.noise, result->sample.ath10k.header.max_magnitude,
		       result->sample.ath10k.header.max_index, result->sample.ath10k.header.tsf);
		printf("datamax = %d, datamin = %d, datasquaresum = %d\n", datamax, datamin, datasquaresum);
	}

	for (i = 0; i < bins; i++) {
		float freq;
		int data;
		freq = result->sample.ath10k.header.freq1 -
				(result->sample.ath10k.header.chan_width_mhz ) / 2 +
				(result->sample.ath10k.header.chan_width_mhz * (i + 0.5) / bins);

		data = result->sample.ath10k.data[i] << result->sample.ath10k.header.max_exp;
		plot_datapoint(pixels, freq, startfreq, result->sample.ath10k.header.noise,
			       result->sample.ath10k.header.rssi, data, datasquaresum,
			       highlight);
	}

	return 0;
}


/*
 * draw_picture - draws the current screen.
 *
 * @highlight: the index of the dataset to be highlighted
 *
 * returns the center frequency of the currently highlighted dataset
 */
int draw_picture(int highlight, int startfreq)
{
	Uint32 *pixels;
	int x, y, i, rnum;
	int highlight_freq = startfreq + 20;
	char text[1024];
	struct scanresult *result;
	SDL_Surface *surface;

	surface = SDL_CreateRGBSurface(SDL_SWSURFACE, WIDTH, HEIGHT, BPP, RMASK, GMASK, BMASK, AMASK);
	pixels = (Uint32 *) surface->pixels;
	for (y = 0; y < HEIGHT; y++)
		for (x = 0; x < WIDTH; x++)
			pixels[x + y * WIDTH] = AMASK;

	/* vertical lines (frequency) */
	for (i = 2300; i < 6000; i += 10) {
		x = (X_SCALE * (i - startfreq));

		if (x < 0 || x > WIDTH)
			continue;

		for (y = 0; y < HEIGHT - 20; y++)
			pixels[x + y * WIDTH] = 0x40404040 | AMASK;

		snprintf(text, sizeof(text), "%d MHz", i);
		render_text(surface, text, x - 30, HEIGHT - 20);
	}

	/* horizontal lines (dBm) */
	for (i = 0; i < 150; i += 10) {
		y = 600 - Y_SCALE * i;
		
		for (x = 0; x < WIDTH; x++)
			pixels[x + y * WIDTH] = 0x40404040 | AMASK;

		snprintf(text, sizeof(text), "-%d dBm", (150 - i));
		render_text(surface, text, 5, y - 15);
	}


	rnum = 0;
	for (result = result_list; result ; result = result->next) {
		switch (result->sample.tlv.type) {
		case ATH_FFT_SAMPLE_HT20:
			if (rnum == highlight)
				highlight_freq = result->sample.ht20.freq;

			draw_sample_ht20(pixels, result, startfreq, rnum == highlight);
			break;
		case ATH_FFT_SAMPLE_ATH10K:
			if (rnum == highlight)
				highlight_freq = result->sample.ath10k.header.freq1;

			draw_sample_ath10k(pixels, result, startfreq, rnum == highlight);
			/* TODO */
			break;
		}
		rnum++;
	}

	SDL_BlitSurface(surface, NULL, screen, NULL);
	SDL_FreeSurface(surface);
	SDL_Flip(screen); 

	return highlight_freq;
}

/* read_file - reads an file into a big buffer and returns it
 *
 * @fname: file name
 *
 * returns the buffer with the files content
 */
char *read_file(char *fname, size_t *size)
{
	FILE *fp;
	char *buf = NULL;
	size_t ret;

	fp = fopen(fname, "r");

	if (!fp)
		return NULL;

	*size = 0;
	while (!feof(fp)) {

		buf = realloc(buf, *size + 4097);
		if (!buf)
			return NULL;

		ret = fread(buf + *size, 1, 4096, fp);
		*size += ret;
	}
	fclose(fp);

	buf[*size] = 0;

	return buf;
}

/*
 * read_scandata - reads the fft scandata and compiles a linked list of datasets
 *
 * @fname: file name
 *
 * returns 0 on success, -1 on error.
 */
int read_scandata(char *fname)
{
	char *pos, *scandata;
	size_t len, sample_len;
	struct scanresult *result;
	struct fft_sample_tlv *tlv;
	struct scanresult *tail = result_list;
	int handled, bins;

	scandata = read_file(fname, &len);
	if (!scandata)
		return -1;

	pos = scandata;

	while (pos - scandata < len) {
#define CONVERT_BE16(val)	val = be16toh(val)
#define CONVERT_BE64(val)	val = be64toh(val)
		tlv = (struct fft_sample_tlv *) pos;
		CONVERT_BE16(tlv->length);
		sample_len = sizeof(*tlv) + tlv->length;
		pos += sample_len;

		if (sample_len > sizeof(*result)) {
			fprintf(stderr, "sample length %d too long\n", sample_len);
			continue;
		}

		result = malloc(sizeof(*result));
		if (!result)
			continue;

		memset(result, 0, sizeof(*result));
		memcpy(&result->sample, tlv, sample_len);

		handled = 0;
		switch (tlv->type) {
		case ATH_FFT_SAMPLE_HT20:
			if (sample_len != sizeof(result->sample.ht20)) {
				fprintf(stderr, "wrong sample length (have %zd, expected %zd)\n",
					sample_len, sizeof(result->sample));
				break;
			}

			CONVERT_BE16(result->sample.ht20.freq);
			CONVERT_BE16(result->sample.ht20.max_magnitude);
			CONVERT_BE64(result->sample.ht20.tsf);

			handled = 1;
			break;
		case ATH_FFT_SAMPLE_ATH10K:
			bins = sample_len - sizeof(result->sample.ath10k.header);

			if (bins != 64 &&
			    bins != 128 &&
			    bins != 256) {
				fprintf(stderr, "invalid bin length %d\n", bins);
				break;
			}

			CONVERT_BE16(result->sample.ath10k.header.freq1);
			CONVERT_BE16(result->sample.ath10k.header.freq2);
			CONVERT_BE16(result->sample.ath10k.header.noise);
			CONVERT_BE16(result->sample.ath10k.header.max_magnitude);
			CONVERT_BE16(result->sample.ath10k.header.total_gain_db);
			CONVERT_BE16(result->sample.ath10k.header.base_pwr_db);
			CONVERT_BE64(result->sample.ath10k.header.tsf);

			handled = 1;
			break;
		default:
			fprintf(stderr, "unknown sample type (%d)\n", tlv->type);
			break;
		}

		if (!handled) {
			free(result);
			continue;
		}

		if (tail)
			tail->next = result;
		else
			result_list = result;

		tail = result;

		scanresults_n++;
	}

	fprintf(stderr, "read %d scan results\n", scanresults_n);
	return 0;
}

/*
 * graphics_main - sets up the data and holds the mainloop.
 *
 */
void graphics_main(char *name)
{
	SDL_Event event;
	int quit = 0;
	int highlight = 0;
	int change = 1, scroll = 0;
	int startfreq = 2350, accel = 0;
	int highlight_freq = startfreq;

	if (graphics_init_sdl(name) < 0) {
		fprintf(stderr, "Failed to initialize graphics.\n");
		return;
	}
	SDL_EnableKeyRepeat(SDL_DEFAULT_REPEAT_DELAY, SDL_DEFAULT_REPEAT_INTERVAL);
	while (!quit) {
		if (change) {
			highlight_freq = draw_picture(highlight, startfreq);
			change = 0;
		}

		if (!scroll) {
			/* move to highlighted object */
			if (highlight_freq - 20 < startfreq)
				accel = -10;
			if (highlight_freq > (startfreq + WIDTH/X_SCALE))
				accel = 10;
			
			/* if we are "far off", move a little bit faster */
			if (highlight_freq + 300 < startfreq)
				accel = -100;
	
			if (highlight_freq - 300 > (startfreq + WIDTH/X_SCALE))
				accel = 100;
		}

		if (accel)
			SDL_PollEvent(&event);
		else
			SDL_WaitEvent(&event);

		switch (event.type) {
		case SDL_QUIT:
			quit = 1;
			break;
		case SDL_KEYDOWN:
			switch (event.key.keysym.sym) {
			case SDLK_LEFT:
				if (highlight > 0) {
					highlight--;
					scroll = 0;
					change = 1;
				}
				break;
			case SDLK_RIGHT:
				if (highlight < scanresults_n - 1){
					highlight++;
					scroll = 0;
					change = 1;
				}
				break;
			case SDLK_PAGEUP:
				accel-= 2;
				scroll = 1;
				break;
			case SDLK_PAGEDOWN:
				accel+= 2;
				scroll = 1;
				break;
			case SDLK_2:
				startfreq = 2370;
				accel +=1;
				scroll = 1;
				break;
			case SDLK_5:
				startfreq = 5150;
				accel +=1;
				scroll = 1;
				break;
			default:
				break;
			}
			break;
		}
		if (accel) {
			startfreq += accel;
			if (accel > 0)			accel--;
			if (accel < 0)			accel++;
			change = 1;
		}
		if (startfreq < 2300)		startfreq = 2300;
		if (startfreq > 6000)		startfreq = 6000;
		if (accel < -20)		accel = -20;
		if (accel >  20)		accel = 20;
	}

	graphics_quit_sdl();
}

void usage(int argc, char *argv[])
{
	fprintf(stderr, "Usage: %s [scanfile]\n", argv[0]);
	fprintf(stderr, "\n");
	fprintf(stderr, "scanfile is generated by the spectral analyzer feature\n");
	fprintf(stderr, "of your wifi card. If you have a AR92xx or AR93xx based\n");
	fprintf(stderr, "card, try:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "ip link set dev wlan0 up\n");
	fprintf(stderr, "echo chanscan > /sys/kernel/debug/ieee80211/phy0/ath9k/spectral_scan_ctl\n");
	fprintf(stderr, "iw dev wlan0 scan\n");
	fprintf(stderr, "cat /sys/kernel/debug/ieee80211/phy0/ath9k/spectral_scan0 > /tmp/fft_results\n");
	fprintf(stderr, "echo disable > /sys/kernel/debug/ieee80211/phy0/ath9k/spectral_scan_ctl\n");
	fprintf(stderr, "%s /tmp/fft_results\n", argv[0]);
	fprintf(stderr, "\n");
	fprintf(stderr, "for AR98xx based cards, you may use:\n");
	fprintf(stderr, "ip link set dev wlan0 up\n");
	fprintf(stderr, "echo background > /sys/kernel/debug/ieee80211/phy0/ath10k/spectral_scan_ctl\n");
	fprintf(stderr, "echo trigger > /sys/kernel/debug/ieee80211/phy0/ath10k/spectral_scan_ctl\n");
	fprintf(stderr, "iw dev wlan0 scan\n");
	fprintf(stderr, "echo disable > /sys/kernel/debug/ieee80211/phy0/ath10k/spectral_scan_ctl\n");
	fprintf(stderr, "cat /sys/kernel/debug/ieee80211/phy0/ath10k/spectral_scan0 > samples\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "(NOTE: maybe debugfs must be mounted first: mount -t debugfs none /sys/kernel/debug/ )\n");
	fprintf(stderr, "\n");

}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage(argc, argv);
		return -1;
	}

	fprintf(stderr, "WARNING: Experimental Software! Don't trust anything you see. :)\n");
	fprintf(stderr, "\n");
	if (read_scandata(argv[1]) < 0) {
		fprintf(stderr, "Couldn't read scanfile ...\n");
		usage(argc, argv);
		return -1;
	}
	graphics_main(argv[1]);

	return 0;
}
