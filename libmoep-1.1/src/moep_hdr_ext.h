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

#ifndef MOEP_HDR_EXT_H
#define MOEP_HDR_EXT_H

#include <moep80211/types.h>


void moep_hdr_ext_destroy(void *ptrs);

int moep_hdr_ext_parse(void *ptrs, u8 **raw, size_t *maxlen);

int moep_hdr_ext_build_len(void *ptrs);

int moep_hdr_ext_build(void *ptrs, u8 *raw, size_t maxlen);

#endif /* MOEP_HDR_EXT_H */
