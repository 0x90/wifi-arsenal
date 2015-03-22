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
 *
 * Dual license: BSD/GPLv2
 */

#ifndef COMMON_DLL_H_
#define COMMON_DLL_H_

#if defined _WIN32 || defined __CYGWIN__
  #define DLL_IMPORT __declspec(dllimport)
  #define DLL_EXPORT __declspec(dllexport)
  #define DLL_HIDDEN
#else
  #if __GNUC__ >= 4
    #define DLL_IMPORT __attribute__ ((visibility ("default")))
    #define DLL_EXPORT __attribute__ ((visibility ("default")))
    #define DLL_HIDDEN  __attribute__ ((visibility ("hidden")))
  #else
    #define DLL_IMPORT
    #define DLL_EXPORT
    #define DLL_HIDDEN
  #endif
#endif

#endif /* COMMON_DLL_H_ */
