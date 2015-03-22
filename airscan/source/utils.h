/**
 * AirScan - utils.h
 *
 * Copyright 2008-2010 Raphaël Rigo
 *
 * For mails :
 * user : devel-nds
 * domain : syscall.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UTIL_H
#define UTIL_H

#define print_to_debug(x) print_to(debugConsole, (x))
#define print_to_main(x) print_to(mainConsole, (x))
#define printf_to_debug(...) printf_to(debugConsole, __VA_ARGS__)
#define printf_to_main(...) printf_to(mainConsole, __VA_ARGS__)
#define print_xy_to_debug(...) print_xy_to(debugConsole, __VA_ARGS__)
#define print_xy(...) print_xy_to(mainConsole, __VA_ARGS__)
#define printf_xy_to_debug(...) printf_xy_to(debugConsole, __VA_ARGS__)
#define printf_xy(...) printf_xy_to(mainConsole, __VA_ARGS__)
#ifdef DEBUG
	#define DEBUG_PRINT(...) do{ printf_to_debug(__VA_ARGS__); } while(false)
#else
	#define DEBUG_PRINT(...) do {} while (0)
#endif


extern PrintConsole *debugConsole, *mainConsole;

void clear_main();
void init_consoles(void);
void print_to(PrintConsole *c, char *str);
void printf_to(PrintConsole *c, char *format, ...);
void print_xy_to(PrintConsole *c, int x, int y, char *str);
void printf_xy_to(PrintConsole *c, int x, int y, char *format, ...);
void abort_msg(char *msg);

#endif
