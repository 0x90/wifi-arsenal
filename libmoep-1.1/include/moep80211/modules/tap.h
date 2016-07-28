/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 * 				Stephan M. Guenther <moepi@moepi.net>
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

/**
 * \defgroup moep80211_modules_tap Tap
 * \ingroup moep80211_module
 * \{
 * \file
 */
#ifndef __MOEP80211_MODULES_TAP_H
#define __MOEP80211_MODULES_TAP_H

#include <netinet/in.h>

#include <moep80211/dev.h>


struct moep_frame_ops;


/**
 * \brief open a tap device
 *
 * The function moep_dev_tap_open() is used to open a tap device.
 *
 * \param addr the hardware address of the device; This can be NULL to be
 * automatically set.
 * \param ip the IP address of the device; This can be NULL to set no IP
 * address.
 * \param prefixlen the length of the IP prefix.
 * \param mtu the MTU of the device; This includes all headers.
 * \param l2_ops frame header operations for layer 2
 *
 * \return This function returns a moep device.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{These are some standard errors generated and returned by this
 * function. Additional errors may be generated and returned from the underlying
 * system calls.}
 * \errval{EINVAL, Invalid argument}
 * \errval{EMFILE, Too many open files; Some filedescriptors are too big for
 * select.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
moep_dev_t moep_dev_tap_open(u8 *addr, const struct in_addr *ip, int prefixlen,
			     int mtu, struct moep_frame_ops *l2_ops);

/**
 * \brief get hardware address
 *
 * The function moep_dev_tap_get_hwaddr() is used to get the hardware address of
 * a tap device.
 *
 * \param dev the tap device
 * \param addr a buffer for the address
 *
 * \retval 0 on success
 * \retval -1 on error, errno is set appropriately.
 *
 * \errors{These are some standard errors generated and returned by this
 * function. Additional errors may be generated and returned from the underlying
 * system calls.}
 * \errval{EACCES, The moep device is not a tap device.}
 * \enderrors
 */
int moep_dev_tap_get_hwaddr(moep_dev_t dev, u8 *addr);

/**
 * \brief create a tap frame
 *
 * The function moep_frame_tap_create() is used to create a tap frame with the
 * given frame header operations for layer 2.
 *
 * \param l2_ops frame header operations for layer 2
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_tap_create(struct moep_frame_ops *l2_ops);

/** \} */
#endif /* __MOEP80211_MODULES_TAP_H */
