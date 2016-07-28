/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 * 				Stephan M. Guenther <moepi@moepi.net>
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

#ifndef __MOEP80211_IEEE80211_ADDR_H
#define __MOEP80211_IEEE80211_ADDR_H

#include <moep80211/types.h>


#define IEEE80211_ALEN			6


u8 *ieee80211_aton(const char* addr);

char *ieee80211_ntoa(const u8 *addr);

#endif /* __MOEP80211_IEEE80211_ADDR_H */
