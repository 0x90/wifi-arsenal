/*
 * OpenWIPS-ng - common stuff.
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

#ifndef COMMON_VERSION_H_
#define COMMON_VERSION_H_

#define _MAJ 0
#define _MIN 1
#define _SUB_MIN 0
#define _BETA 1
#define _RC 0
#define WEBSITE "http://openwips-ng.org"

#ifndef _REVISION
#define _REVISION 0
#endif

char * getVersion(char * progname, int maj, int min, int submin, int
			 svnrev, int beta, int rc);


#endif /* COMMON_VERSION_H_ */
