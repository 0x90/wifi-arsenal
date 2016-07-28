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

#ifndef INTERFACES_H
#define INTERFACES_H

#include <netinet/in.h>

#include <moep80211/types.h>


int get_number_from_file(const char *path, const char *name);

int get_ifindex(const char *name);

int set_link(int ifindex, u8 *addr, int mtu);

int get_link_addr(int ifindex, u8 *addr);

int set_ipaddr(int ifindex, const struct in_addr *addr, int prefixlen);

#endif /* INTERFACES_H */
