/*
 * Linux Wireless Extensions support
 *
 * Copyright (C) 1999-2012, Broadcom Corporation
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 * $Id: wl_roam.c 302026 2011-12-09 11:51:50Z $
 */
#include <typedefs.h>
#include <osl.h>
#include <bcmwifi_channels.h>
#include <wlioctl.h>

#define WL_DBG(x)

#define MAX_ROAM_CACHE 100

typedef struct {
	chanspec_t chanspec;
	int ssid_len;
	char ssid[36];
} roam_channel_cache;

static int n_roam_cache = 0;
static int roam_band = WLC_BAND_AUTO;
static roam_channel_cache roam_cache[MAX_ROAM_CACHE];

void set_roam_band(int band)
{
	roam_band = band;
}

void reset_roam_cache(void)
{
	n_roam_cache = 0;
}

void add_roam_cache(wl_bss_info_t *bi)
{
	int i;
	uint8 channel;

	if (n_roam_cache == MAX_ROAM_CACHE)
		return;

	for (i = 0; i < n_roam_cache; i++) {
		if ((roam_cache[i].ssid_len == bi->SSID_len) &&
		    (roam_cache[i].chanspec == bi->chanspec) &&
		    (memcmp(roam_cache[i].ssid, bi->SSID, bi->SSID_len) == 0)) {
			/* identical one found, just return */
			return;
		}
	}

	roam_cache[n_roam_cache].ssid_len = bi->SSID_len;
	channel = (bi->ctl_ch == 0) ? CHSPEC_CHANNEL(bi->chanspec) : bi->ctl_ch;
	roam_cache[n_roam_cache].chanspec = WL_CHANSPEC_BW_20 | WL_CHANSPEC_CTL_SB_NONE | (channel <= 14 ? WL_CHANSPEC_BAND_2G : WL_CHANSPEC_BAND_5G) | channel;
	memcpy(roam_cache[n_roam_cache].ssid, bi->SSID, bi->SSID_len);

	n_roam_cache++;
}

int get_roam_channel_list(int target_chan, chanspec_t *channels, const wlc_ssid_t *ssid)
{
	int i, n = 1;
	uint band;

	WL_DBG((" %s: %02d\n", __FUNCTION__, target_chan));

	if (target_chan <= 14)
		band = WL_CHANSPEC_BAND_2G;
	else
		band = WL_CHANSPEC_BAND_5G;
	*channels++ = (target_chan & WL_CHANSPEC_CHAN_MASK) | band | WL_CHANSPEC_BW_20 | WL_CHANSPEC_CTL_SB_NONE;

	for(i=0; i<n_roam_cache; i++) {
		chanspec_t ch = roam_cache[i].chanspec;
		if ((roam_cache[i].ssid_len == ssid->SSID_len) &&
			((ch & WL_CHANSPEC_CHAN_MASK) != target_chan) &&
			((roam_band == WLC_BAND_AUTO) || ((roam_band == WLC_BAND_2G) && CHSPEC_IS2G(ch)) || ((roam_band == WLC_BAND_5G) && CHSPEC_IS5G(ch))) &&
			(memcmp(roam_cache[i].ssid, ssid->SSID, ssid->SSID_len) == 0)) {
			/* match found, add it */
			*channels = ch & WL_CHANSPEC_CHAN_MASK;
			if (*channels <= 14)
				*channels |= WL_CHANSPEC_BAND_2G | WL_CHANSPEC_BW_20 | WL_CHANSPEC_CTL_SB_NONE;
			else
				*channels |= WL_CHANSPEC_BAND_5G | WL_CHANSPEC_BW_20 | WL_CHANSPEC_CTL_SB_NONE;
			WL_DBG((" %s: %02d 0x%04X\n", __FUNCTION__, ch & WL_CHANSPEC_CHAN_MASK, *channels));
			channels++; n++;
		}
	}

	return n;
}


void print_roam_cache(void)
{
	int i;

	WL_DBG((" %d cache\n", n_roam_cache));

	for (i = 0; i < n_roam_cache; i++) {
		roam_cache[i].ssid[roam_cache[i].ssid_len] = 0;
		WL_DBG(("0x%02X %02d %s\n", roam_cache[i].chanspec, roam_cache[i].ssid_len, roam_cache[i].ssid));
	}
}
