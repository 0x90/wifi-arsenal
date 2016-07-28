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
#include <signal.h>
#include <time.h>

#include <sys/select.h>

#include <moep80211/types.h>
#include <moep80211/frame.h>
#include <moep80211/dev.h>
#include <moep80211/system.h>

#include "dev.h"
#include "list.h"
#include "util.h"


static void __moep80211_rx(moep_dev_t dev)
{
	moep_frame_t frame;
	u8 *data;
	int len;

	if (!(data = malloc(dev->mtu))) {
		// TODO error
		return;
	}

	do {
		len = read(dev->fd, data, dev->mtu);
	} while (len < 0 && errno == EINTR);
	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			// TODO error
		}
		free(data);
		return;
	}

	if (dev->rx_raw)
		dev->rx_raw(dev, data, len);

	if (dev->rx) {
		if (!(frame = moep_dev_frame_decode(dev, data, len))) {
			//TODO error
			free(data);
			return;
		}
		dev->rx(dev, frame);
	}

	free(data);
}

static void __moep80211_tx(moep_dev_t dev)
{
	struct frame *f, *tmp;
	int ret;
	u64 event;

	list_for_each_entry_safe(f, tmp, &dev->frame_queue, list) {
		do {
			ret = write(dev->fd, f->data, f->len);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				// TODO error
				list_del(&f->list);
				free(f->data);
				free(f);
			}
			return;
		}
		if (ret != f->len) {
			// TODO error
		}
		list_del(&f->list);
		free(f->data);
		free(f);
	}

	if (list_empty(&dev->frame_queue)) {
		event = 1;
		do {
			ret = write(dev->tx_event, &event, 8);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				// TODO error
			}
		}
	}
}

int moep_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exeptfds,
		const struct timespec *timeout, const sigset_t *sigmask)
{
	fd_set ior, iow, ioe, sior, siow, sioe, rxevt;
	int ret;
	struct moep_dev *dev, tmp;
	struct timespec timeout_clock, timeout_time, timeout_tmp;

	if (timeout) {
		clock_gettime(CLOCK_REALTIME, &timeout_clock);
		timespecadd(&timeout_clock, timeout);
		timeout = &timeout_time;
	}

	if (!readfds) {
		FD_ZERO(&ior);
		readfds = &ior;
	}
	if (!writefds) {
		FD_ZERO(&iow);
		writefds = &iow;
	}
	if (!exeptfds) {
		FD_ZERO(&ioe);
		exeptfds = &ioe;
	}
	sior = *readfds;
	siow = *writefds;
	sioe = *exeptfds;

	/*
	 * TODO
	 * allow removing of devices during __moep80211_rx
	 */
	list_for_each_entry(dev, &moep_dev_list, list) {
		if (dev->rx_event >= 0) {
			FD_SET(dev->rx_event, &sior);
			nfds = max(nfds, dev->rx_event + 1);
		}
	}

	do {
		*readfds = sior;
		*writefds = siow;
		*exeptfds = sioe;

		list_for_each_entry(dev, &moep_dev_list, list) {
			if (!list_empty(&dev->frame_queue)) {
				FD_SET(dev->fd, writefds);
				nfds = max(nfds, dev->fd + 1);
			}
		}

		if (timeout) {
			timeout_time = timeout_clock;
			clock_gettime(CLOCK_REALTIME, &timeout_tmp);
			timespecsub(&timeout_time, &timeout_tmp);
			if (timeout_time.tv_sec < 0 || (timeout_time.tv_sec == 0
			    && timeout_time.tv_nsec < 0)) {
				timeout_time.tv_sec = 0;
				timeout_time.tv_nsec = 0;
			}
		}

		ret = pselect(nfds, readfds, writefds, exeptfds, timeout,
			      sigmask);
		if (ret <= 0)
			return ret;

		list_for_each_entry_extra_safe(dev, &tmp, &moep_dev_list, list) {
			if (FD_ISSET(dev->fd, readfds)) {
				FD_ZERO(&rxevt);
				FD_SET(dev->rx_event, &rxevt);
				timeout_tmp.tv_nsec = 0;
				timeout_tmp.tv_sec = 0;
				pselect(dev->rx_event+1, &rxevt, NULL, NULL,
					&timeout_tmp, sigmask);
				if (FD_ISSET(dev->rx_event, &rxevt)) {
					__moep80211_rx(dev);
				}
				FD_CLR(dev->fd, readfds);
				ret -= 1;
				FD_CLR(dev->fd, &sior);
				if (dev->rx_event >= 0) {
					FD_SET(dev->rx_event, &sior);
					nfds = max(nfds, dev->rx_event + 1);
				}
			} else if (dev->rx_event >= 0 &&
				   FD_ISSET(dev->rx_event, readfds)) {
				FD_CLR(dev->rx_event, readfds);
				ret -= 1;
				FD_CLR(dev->rx_event, &sior);
				FD_SET(dev->fd, &sior);
				nfds = max(nfds, dev->fd + 1);
			}
		} list_end_entry_extra_safe(&tmp, list);
		list_for_each_entry(dev, &moep_dev_list, list) {
			if (FD_ISSET(dev->fd, writefds)) {
				__moep80211_tx(dev);
				FD_CLR(dev->fd, writefds);
				ret -= 1;
			}
		}
	} while (ret == 0);
	if (ret < 0) {
		/*
		 * TODO
		 * We should not ignore this error since one should never ignore
		 * an error, but we should never get here, because if we get
		 * here something went completely wrong and the select call
		 * seems to be broken.
		 */
	}

	return ret;
}

int moep_run(sig_handler sigh)
{
	sigset_t blockset, oldset;
	int err;

	sigfillset(&blockset);
	if (sigprocmask(SIG_SETMASK, &blockset, &oldset))
		return -1;
	if (sigh)
		sigh();

	for(;;) {
		if (moep_select(0, NULL, NULL, NULL, NULL, &oldset) < 0) {
			if (errno == EINTR) {
				if (sigh) {
					if ((err = sigh()))
						return err;
				}
			}
			else {
				err = errno;
				sigprocmask(SIG_SETMASK, &oldset, NULL);
				errno = err;
				return -1;
			}
		}
	}
}
