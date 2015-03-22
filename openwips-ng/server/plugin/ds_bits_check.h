/*
 * OpenWIPS-ng server plugin: Check FromDS and ToDS bits.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */

#ifndef DS_BITS_CHECK_H_
#define DS_BITS_CHECK_H_

struct ds_bits_check_config {
	unsigned short sn;
	unsigned char type;
	unsigned char subtype;
	struct pcap_packet * frame;

	int is_attacked;
};


#endif /* DS_BITS_CHECK_H_ */
