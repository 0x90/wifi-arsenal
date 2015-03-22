/*
 * OpenWIPS-ng server plugin: Frame replay detection.
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

#ifndef REPLAY_DETECT_H_
#define REPLAY_DETECT_H_

struct replay_attack {
	char * attack;
	char address1[6], address2[6], address3[6], address4[6];
	int attack_returned;

	struct replay_attack * next;
};

struct replay_attack * init_new_replay_attack_strut();
#endif // REPLAY_DETECT_H_
