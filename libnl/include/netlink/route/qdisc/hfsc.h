/*
 * netlink/route/sch/hfsc.h	HFSC Qdisc
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2014 Cong Wang <xiyou.wangcong@gmail.com>
 */

#ifndef NETLINK_HFSC_H_
#define NETLINK_HFSC_H_

#include <netlink/netlink.h>
#include <netlink/route/tc.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/class.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t	rtnl_qdisc_hfsc_get_defcls(const struct rtnl_qdisc *);
extern int	rtnl_qdisc_hfsc_set_defcls(struct rtnl_qdisc *, uint32_t);

extern int rtnl_class_hfsc_get_rsc(const struct rtnl_class *class, struct tc_service_curve *tsc);
extern int rtnl_class_hfsc_set_rsc(struct rtnl_class *class, const struct tc_service_curve *tsc);
extern int rtnl_class_hfsc_get_fsc(const struct rtnl_class *class, struct tc_service_curve *tsc);
extern int rtnl_class_hfsc_set_fsc(struct rtnl_class *class, const struct tc_service_curve *tsc);
extern int rtnl_class_hfsc_get_usc(const struct rtnl_class *class, struct tc_service_curve *tsc);
extern int rtnl_class_hfsc_set_usc(struct rtnl_class *class, const struct tc_service_curve *tsc);
#ifdef __cplusplus
}
#endif

#endif
