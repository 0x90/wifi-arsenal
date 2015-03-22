/*
 * OpenWIPS-ng sensor.
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

#ifndef STATE_MACHINE_H_
#define STATE_MACHINE_H_

#define STATE_NOT_CONNECTED		-1
#define STATE_CONNECTED			 0 // Can send VERSION
#define STATE_VERSION			 1 // Can send LOGIN
#define STATE_LOGIN				 2 // Can send PASS
#define STATE_LOGGED_IN			 3 // Can send GET_CONFIG
#define STATE_LOGIN_FAILED		 4 // Can't send anything


#endif /* STATE_MACHINE_H_ */
