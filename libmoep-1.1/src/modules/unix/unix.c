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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/fcntl.h>

#include <linux/un.h>

#include <moep80211/types.h>
#include <moep80211/module.h>

#include <moep80211/modules/unix.h>


moep_frame_t moep_frame_unix_create(struct moep_frame_ops *l2_ops)
{
	return moep_frame_create(NULL, l2_ops);
}

struct unix_priv {
	int ifindex;
};

static int unix_close(int fd, void *priv)
{
	return close(fd);
}

static struct moep_dev_ops unix_dev_ops = {
	.close		= unix_close,
};

moep_dev_t moep_dev_unix_open(const char *devname, int mtu,
			      struct moep_frame_ops *l2_ops)
{
	moep_dev_t dev;
	int fd;
	struct sockaddr_un addr;
	int err;

	if ((fd = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0)) < 0) {
		return NULL;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, devname, UNIX_PATH_MAX);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		err = errno;
		close(fd);
		errno = err;
		return NULL;
	}

	if (!(dev = moep_dev_open(fd, mtu, &unix_dev_ops, NULL, NULL,
				  l2_ops))) {
		err = errno;
		close(fd);
		errno = err;
		return NULL;
	}

	return dev;
}
