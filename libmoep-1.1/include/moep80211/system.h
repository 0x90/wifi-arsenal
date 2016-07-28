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
 * \defgroup moep80211_system System
 * \brief The System API is used to operate the moep system.
 *
 * \{
 * \file
 */
#ifndef __MOEP80211_SYSTEM_H
#define __MOEP80211_SYSTEM_H

#include <sys/select.h>


/**
 * \brief synchronous I/O multiplexing
 *
 * The moep_select() call allows a program to monitor multiple file descriptors,
 * waiting until one or more of the file descriptors become "ready" for some
 * class of I/O operation. The call works similiar to pselect() and the
 * parameters are identical. See the respective manual page for more details.
 * The difference to pselect() is, that moep_select() schedules the internal
 * moep devices during waiting.
 *
 * \return The return values are the same as for pselect().
 *
 * \errors{The error values are the same as for pselect().}
 * \enderrors
 */
int moep_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exeptfds,
		const struct timespec *timeout, const sigset_t *sigmask);

/**
 * \brief a signal handler
 *
 * A sig_handler() is a function pointer that is called by moep_run() after an
 * interrupt.
 *
 * \return The signal handler must either return 0, or moep_run() returns with
 * this return value.
 */
typedef int (* sig_handler)(void);

/**
 * \brief run the moep multiplexer
 *
 * The moep_run() call is similiar to calling moep_select() with mostly NULLs in
 * a loop. This call is useful if no additional file descriptors need to be
 * watched. If a signal occured this call does not return but calls
 * \paramname{sigh} instead. If \paramname{sigh} is NULL signals are ignored.
 *
 * \param sigh the signal handler
 *
 * \return This call does not return until an error occured.
 * \retval -1 on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_select(), except that
 * \errno{EINTR} is handled internally.}
 * \enderrors
 */
int moep_run(sig_handler sigh);

/** \} */
#endif /* __MOEP80211_SYSTEM_H */
