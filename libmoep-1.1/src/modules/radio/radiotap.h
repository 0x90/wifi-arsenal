/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 *				Stephan M. Guenther <moepi@moepi.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See COPYING for more details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RADIOTAP_H
#define RADIOTAP_H

#include <moep80211/radiotap.h>
#include <moep80211/types.h>


u16 radiotap_len(u32 present);

int radiotap_parse(struct moep80211_radiotap *moep_hdr,
		   struct ieee80211_radiotap_header *ieee_hdr, int len);

int radiotap_build(struct moep80211_radiotap *moep_hdr,
		   struct ieee80211_radiotap_header *ieee_hdr, int len);

#endif /* RADIOTAP_H */
