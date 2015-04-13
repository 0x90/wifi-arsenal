/*
 * netlink/route/link/inet6.h	INET6 Link Module
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2014 Dan Williams <dcbw@redhat.com>
 */

#ifndef NETLINK_LINK_INET6_H_
#define NETLINK_LINK_INET6_H_

#include <netlink/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *		rtnl_link_inet6_addrgenmode2str  (uint8_t mode,
							  char *buf,
							  size_t len);

uint8_t			rtnl_link_inet6_str2addrgenmode  (const char *mode);

extern int		rtnl_link_inet6_get_token(struct rtnl_link *,
						  struct nl_addr **);

extern int		rtnl_link_inet6_set_token(struct rtnl_link *,
						  struct nl_addr *);

extern int		rtnl_link_inet6_get_addr_gen_mode(struct rtnl_link *,
							  uint8_t *);

extern int		rtnl_link_inet6_set_addr_gen_mode(struct rtnl_link *,
							  uint8_t);

#ifdef __cplusplus
}
#endif

#endif
