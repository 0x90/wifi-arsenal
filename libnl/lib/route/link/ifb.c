/*
 * lib/route/link/ifb.c	IFB Interfaces
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2014 Cong Wang <xiyou.wangcong@gmail.com>
 */

/**
 * @ingroup link
 * @defgroup ifb Intermediate Functional Block
 *
 * @details
 * \b Link Type Name: "ifb"
 *
 * @{
 */

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink-private/route/link/api.h>

static struct rtnl_link_info_ops ifb_info_ops = {
	.io_name		= "ifb",
};

static void __init ifb_init(void)
{
	rtnl_link_register_info(&ifb_info_ops);
}

static void __exit ifb_exit(void)
{
	rtnl_link_unregister_info(&ifb_info_ops);
}

/** @} */
