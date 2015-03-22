/*
 * OpenWIPS-ng server plugin: Deauthentication (directed/broadcast) detection.
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

#ifndef DEAUTH_DETECT_H_
#define DEAUTH_DETECT_H_

#include "../common/pcap.h"

struct deauth_attack_struct {
	int is_broadcast;
	int is_attacked;
	int is_aireplay;
	struct pcap_packet * last_packet;
	unsigned char source_mac[6];
	unsigned char dest_mac[6];
};

#endif /* DEAUTH_DETECT_H_ */
