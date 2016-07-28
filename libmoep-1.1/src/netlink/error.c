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

#include <errno.h>

#include <netlink/errno.h>

#include "../util.h"

#include "error.h"


/*
 * This is a bit ugly as syserr2nlerr as well as nlerr2syserr are both not
 * injectiv. This means we have an information loss. Blame the libnl devs.
 */
int nlerr2syserr(int error)
{
	error = abs(error);

	switch (error) {
	case NLE_SUCCESS:		return 0;
	case NLE_FAILURE:		return EFAULT;
	case NLE_INTR:			return EINTR;
	case NLE_BAD_SOCK:		return EBADF;
	case NLE_AGAIN:			return EAGAIN;
	case NLE_NOMEM:			return ENOMEM;
	case NLE_EXIST:			return EEXIST;
	case NLE_INVAL:			return EINVAL;
	case NLE_RANGE:			return ERANGE;
	case NLE_MSGSIZE:		return EMSGSIZE;
	case NLE_OPNOTSUPP:		return EOPNOTSUPP;
	case NLE_AF_NOSUPPORT:		return EAFNOSUPPORT;
	case NLE_OBJ_NOTFOUND:		return ENOENT;
/*	case NLE_NOATTR:		*/
/*	case NLE_MISSING_ATTR:		*/
/*	case NLE_AF_MISMATCH:		*/
/*	case NLE_SEQ_MISMATCH:		*/
	case NLE_MSG_OVERFLOW:		return EMSGSIZE;
	case NLE_MSG_TRUNC:		return EMSGSIZE;
	case NLE_NOADDR:		return EADDRNOTAVAIL;
/*	case NLE_SRCRT_NOSUPPORT:	*/
	case NLE_MSG_TOOSHORT:		return EMSGSIZE;
/*	case NLE_MSGTYPE_NOSUPPORT:	*/
/*	case NLE_OBJ_MISMATCH:		*/
/*	case NLE_NOCACHE:		*/
	case NLE_BUSY:			return EBUSY;
	case NLE_PROTO_MISMATCH:	return EPROTONOSUPPORT;
	case NLE_NOACCESS:		return EACCES;
	case NLE_PERM:			return EPERM;
/*	case NLE_PKTLOC_FILE:		*/
/*	case NLE_PARSE_ERR:		*/
	case NLE_NODEV:			return ENODEV;
/*	case NLE_IMMUTABLE:		*/
/*	case NLE_DUMP_INTR:		*/
	default:			return EFAULT;
	}
}
