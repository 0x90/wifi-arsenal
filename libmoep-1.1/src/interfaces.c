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

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <netpacket/packet.h>

#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <linux/if.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <netlink/route/link.h>
#include <netlink/route/addr.h>

#include "netlink/util.h"
#include "netlink/error.h"

#include "interfaces.h"
#include "util.h"


int get_number_from_file(const char *path, const char *name)
{
	char strbuf[512];
	int fd;
	int err;

	err = snprintf(strbuf, sizeof(strbuf), path, name);
	if (err < 0 || err >= sizeof(strbuf)) {
		errno = EFAULT;
		return -1;
	}
	if ((fd = open(strbuf, O_RDONLY)) < 0)
		return -1;

	if ((err = read(fd, strbuf, sizeof(strbuf) - 1)) < 0) {
		err = errno;
		close(fd);
		errno = err;
		return -1;
	}
	strbuf[err] = '\0';

	errno = 0;
	err = strtol(strbuf, NULL, 10);
	if (errno) {
		err = errno;
		close(fd);
		errno = err;
		return -1;
	}

	close(fd);
	return err;
}

int get_ifindex(const char *name)
{
	return get_number_from_file("/sys/class/net/%s/ifindex", name);
}

int set_link(int ifindex, u8 *addr, int mtu)
{
	struct nl_sock *sock;
	struct rtnl_link *link;
	struct nl_addr* nladdr;
	int err;

	if (!(link = rtnl_link_alloc())) {
		errno = ENOMEM;
		return -1;
	}

	if (!(sock = nl_socket_alloc())) {
		rtnl_link_put(link);
		errno = ENOMEM;
		return -1;
	}
	if ((err = nl_connect(sock, NETLINK_ROUTE))) {
		nl_socket_free(sock);
		rtnl_link_put(link);
		errno = nlerr2syserr(err);
		return -1;
	}

	rtnl_link_set_ifindex(link, ifindex);
	if (addr) {
		if (!(nladdr = nl_addr_build(AF_LLC, addr, 6))) {
			nl_socket_free(sock);
			rtnl_link_put(link);
			errno = ENOMEM;
			return -1;
		}
		rtnl_link_set_addr(link, nladdr);
		nl_addr_put(nladdr);
	}
	if (mtu)
		rtnl_link_set_mtu(link, mtu);
	rtnl_link_set_flags(link, IFF_UP);

	if ((err = rtnl_link_add(sock, link, 0)) < 0) {
		nl_socket_free(sock);
		rtnl_link_put(link);
		errno = nlerr2syserr(err);
		return -1;
	}

	nl_socket_free(sock);
	rtnl_link_put(link);
	return 0;
}

static int set_link_down(int ifindex)
{
	struct nl_sock *sock;
	struct rtnl_link *link;
	int err;

	if (!(link = rtnl_link_alloc())) {
		errno = ENOMEM;
		return -1;
	}

	if (!(sock = nl_socket_alloc())) {
		rtnl_link_put(link);
		errno = ENOMEM;
		return -1;
	}
	if ((err = nl_connect(sock, NETLINK_ROUTE))) {
		nl_socket_free(sock);
		rtnl_link_put(link);
		errno = nlerr2syserr(err);
		return -1;
	}

	rtnl_link_set_ifindex(link, ifindex);
	rtnl_link_unset_flags(link, IFF_UP);

	if ((err = rtnl_link_add(sock, link, 0)) < 0) {
		nl_socket_free(sock);
		rtnl_link_put(link);
		errno = nlerr2syserr(err);
		return -1;
	}

	nl_socket_free(sock);
	rtnl_link_put(link);
	return 0;
}

static int del_link(const char *name)
{
	struct nl_sock *sock;
	struct rtnl_link *link;
	int err;

	if (!(sock = nl_socket_alloc())) {
		errno = ENOMEM;
		return -1;
	}
	if ((err = nl_connect(sock, NETLINK_ROUTE))) {
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}

	if (!(link = rtnl_link_alloc())) {
		nl_socket_free(sock);
		errno = ENOMEM;
		return -1;
	}

	rtnl_link_set_name(link, name);

	if ((err = rtnl_link_delete(sock, link)) < 0) {
		rtnl_link_put(link);
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}

	rtnl_link_put(link);
	nl_socket_free(sock);
	return 0;
}

int get_link_addr(int ifindex, u8 *addr)
{
	struct nl_sock *sock;
	struct rtnl_link *link;
	struct nl_addr* nladdr;
	int err;

	if (!(sock = nl_socket_alloc())) {
		errno = ENOMEM;
		return -1;
	}
	if ((err = nl_connect(sock, NETLINK_ROUTE))) {
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}

	if ((err = rtnl_link_get_kernel(sock, ifindex, NULL, &link)) < 0) {
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}

	nladdr = rtnl_link_get_addr(link);
	if (nl_addr_get_family(nladdr) != AF_LLC) {
		rtnl_link_put(link);
		nl_socket_free(sock);
		errno = EINVAL;
		return -1;
	}
	if (nl_addr_get_len(nladdr) != 6) {
		rtnl_link_put(link);
		nl_socket_free(sock);
		errno = EINVAL;
		return -1;
	}
	memcpy(addr, nl_addr_get_binary_addr(nladdr), 6);

	rtnl_link_put(link);
	nl_socket_free(sock);
	return 0;
}

static in_addr_t bc_addr(in_addr_t addr, int prefixlen)
{
	return addr | htonl(BIT_MASK(32 - prefixlen));
}

int set_ipaddr(int ifindex, const struct in_addr *addr, int prefixlen)
{
	struct nl_sock *sock;
	struct nl_addr* nladdr;
	struct rtnl_addr* rtnladdr;
	in_addr_t bcaddr;
	int err;

	bcaddr = bc_addr(addr->s_addr, prefixlen);

	if (!(sock = nl_socket_alloc())) {
		errno = ENOMEM;
		return -1;
	}
	if ((err = nl_connect(sock, NETLINK_ROUTE))) {
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}

	if (!(rtnladdr = rtnl_addr_alloc())) {
		nl_socket_free(sock);
		errno = ENOMEM;
		return -1;
	}

	rtnl_addr_set_ifindex(rtnladdr, ifindex);

	if (!(nladdr = nl_addr_build(AF_INET, (void *)&addr->s_addr, 4))) {
		rtnl_addr_put(rtnladdr);
		nl_socket_free(sock);
		errno = ENOMEM;
		return -1;
	}
	if ((err = rtnl_addr_set_local(rtnladdr, nladdr)) < 0) {
		nl_addr_put(nladdr);
		rtnl_addr_put(rtnladdr);
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}
	nl_addr_put(nladdr);

	if (!(nladdr = nl_addr_build(AF_INET, (void *)&bcaddr, 4))) {
		rtnl_addr_put(rtnladdr);
		nl_socket_free(sock);
		errno = ENOMEM;
		return -1;
	}
	if ((err = rtnl_addr_set_broadcast(rtnladdr, nladdr)) < 0) {
		nl_addr_put(nladdr);
		rtnl_addr_put(rtnladdr);
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}
	nl_addr_put(nladdr);

	rtnl_addr_set_prefixlen(rtnladdr, prefixlen);

	if ((err = rtnl_addr_add(sock, rtnladdr, 0)) < 0) {
		rtnl_addr_put(rtnladdr);
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}

	rtnl_addr_put(rtnladdr);
	nl_socket_free(sock);
	return 0;
}
