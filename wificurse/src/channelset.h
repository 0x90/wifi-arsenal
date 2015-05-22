/*
    wificurse - WiFi Jamming tool
    Copyright (C) 2012  oblique

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef CHANNELSET_H
#define CHANNELSET_H

#include <stdint.h>

#define CHANNEL_MAX 255
typedef uint32_t channelset_t[8];

static inline void channel_zero(channelset_t *cs) {
	uint32_t *c = (uint32_t*)cs;
	c[0] = c[1] = c[2] = c[3] = 0;
	c[4] = c[5] = c[6] = c[7] = 0;
}

static inline void channel_set(channelset_t *cs, uint8_t chan) {
	uint32_t *c = (uint32_t*)cs;
	c[chan/32] |= 1 << (chan % 32);
}

static inline void channel_unset(channelset_t *cs, uint8_t chan) {
	uint32_t *c = (uint32_t*)cs;
	c[chan/32] &= ~(1 << (chan % 32));
}

static inline int channel_isset(channelset_t *cs, uint8_t chan) {
	uint32_t *c = (uint32_t*)cs;
	return !!(c[chan/32] & (1 << (chan % 32)));
}

static inline void channel_copy(channelset_t *dest, channelset_t *src) {
	uint32_t i, *dc, *sc;
	dc = (uint32_t*)dest;
	sc = (uint32_t*)src;
	for (i=0; i<8; i++)
		dc[i] = sc[i];
}

#endif
