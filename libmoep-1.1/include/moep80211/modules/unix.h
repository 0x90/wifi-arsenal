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
 * \defgroup moep80211_modules_unix Unix
 * \ingroup moep80211_module
 * \{
 * \file
 */
#ifndef __MOEP80211_MODULES_UNIX_H
#define __MOEP80211_MODULES_UNIX_H

#include <moep80211/dev.h>


struct moep_frame_ops;


/**
 * \brief open a unix device
 *
 * The function moep_dev_unix_open() is used to open a unix device.
 *
 * \param devname the device name; This must be the path of a unix domain
 * socket.
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
moep_dev_t moep_dev_unix_open(const char *devname, int mtu,
			      struct moep_frame_ops *l2_ops);

/**
 * \brief create a unix frame
 *
 * The function moep_frame_unix_create() is used to create a unix frame with the
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
moep_frame_t moep_frame_unix_create(struct moep_frame_ops *l2_ops);

/** \} */
#endif /* __MOEP80211_MODULES_UNIX_H */
