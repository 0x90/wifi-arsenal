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
 * \defgroup moep80211_modules_ieee8023 ieee8023
 * \ingroup moep80211_module
 * \{
 * \file
 */
#ifndef __MOEP80211_MODULES_IEEE8023_H
#define __MOEP80211_MODULES_IEEE8023_H

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <moep80211/dev.h>
#include <moep80211/frame.h>

#include <moep80211/modules/eth.h>
#include <moep80211/modules/tap.h>
#include <moep80211/modules/unix.h>


/**
 * \brief open an ieee8023 device
 *
 * The function moep_dev_ieee8023_open() is used to open an ieee8023 device.
 *
 * \param devname, the device name, e.g. eth0
 * \param addr the hardware address of the device; This can be NULL to be
 * automatically set.
 * \param ip the IP address of the device; This can be NULL to set no IP
 * address.
 * \param prefixlen the length of the IP prefix.
 * \param mtu the MTU of the device; This includes all headers.
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
moep_dev_t moep_dev_ieee8023_open(const char *devname, u8 *addr,
				  const struct in_addr *ip, int prefixlen,
				  int mtu);

/**
 * \brief open an ieee8023 tap device
 *
 * The function moep_dev_ieee8023_tap_open() is used to open an ieee8023 tap
 * device.
 *
 * \param addr the hardware address of the device; This can be NULL to be
 * automatically set.
 * \param ip the IP address of the device; This can be NULL to set no IP
 * address.
 * \param prefixlen the length of the IP prefix.
 * \param mtu the MTU of the device; This includes all headers.
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
moep_dev_t moep_dev_ieee8023_tap_open(u8 *addr, const struct in_addr *ip,
				      int prefixlen, int mtu);

/**
 * \brief open an ieee8023 unix device
 *
 * The function moep_dev_ieee8023_unix_open() is used to open an ieee8023 unix
 * device.
 *
 * \param devname the device name; This must be the path of a unix domain
 * socket.
 * \param mtu the MTU of the device; This includes all headers.
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
moep_dev_t moep_dev_ieee8023_unix_open(const char *devname, int mtu);

/**
 * \brief create an ieee8023 frame
 *
 * The function moep_frame_ieee8023_create() is used to create an ieee8023
 * frame.
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_ieee8023_create(void);

/**
 * \brief create an ieee8023 tap frame
 *
 * The function moep_frame_ieee8023_tap_create() is used to create an ieee8023
 * tap frame.
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_ieee8023_tap_create(void);

/**
 * \brief create an ieee8023 unix frame
 *
 * The function moep_frame_ieee8023_unix_create() is used to create an ieee8023
 * unix frame.
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_ieee8023_unix_create(void);

/**
 * \brief ieee8023 header
 *
 * The function moep_frame_ieee8023_hdr() is used to get the ieee8023 header of
 * a frame.
 *
 * \param frame the frame
 *
 * \return This function returns the ieee8023 header.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not an ieee8023 frame.}
 * \errval{ENOMEM, Not enough memory available.}
 * \enderrors
 */
struct ether_header *moep_frame_ieee8023_hdr(moep_frame_t frame);

/** \} */
#endif /* __MOEP80211_MODULES_IEEE8023_H */
