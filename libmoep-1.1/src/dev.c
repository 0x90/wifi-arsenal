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

#include <sys/eventfd.h>

#include <moep80211/frame.h>
#include <moep80211/dev.h>
#include <moep80211/module.h>

#include "dev.h"


#define assert_module(dev, ops, ret)		\
	if ((dev)->ops.close != (ops)->close) {	\
		errno = EACCES;			\
		return ret;			\
	}


LIST_HEAD(moep_dev_list);


moep_dev_t moep_dev_open(int fd, int mtu, struct moep_dev_ops *ops, void *priv,
			 struct moep_frame_ops *l1_ops,
			 struct moep_frame_ops *l2_ops)
{
	moep_dev_t dev;
	int err;

	if (fd < 0) {
		errno = EINVAL;
		return NULL;
	}
	if (fd >= FD_SETSIZE) {
		errno = EMFILE;
		return NULL;
	}
	if (mtu <= 0) {
		errno = EINVAL;
		return NULL;
	}

	if (!(dev = malloc(sizeof(*dev)))) {
		errno = ENOMEM;
		return NULL;
	}
	memset(dev, 0, sizeof(*dev));

	dev->fd = fd;
	dev->mtu = mtu;
	if (ops)
		dev->ops = *ops;
	dev->priv = priv;
	if (l1_ops)
		dev->l1_ops = *l1_ops;
	if (l2_ops)
		dev->l2_ops = *l2_ops;

	if ((dev->tx_event = eventfd(1, EFD_NONBLOCK | EFD_SEMAPHORE)) < 0) {
		err = errno;
		free(dev);
		errno = err;
		return NULL;
	}
	if (dev->tx_event >= FD_SETSIZE) {
		close(dev->tx_event);
		free(dev);
		errno = EMFILE;
		return NULL;
	}
	dev->rx_event = -1;

	INIT_LIST_HEAD(&dev->frame_queue);
	list_add(&dev->list, &moep_dev_list);

	return dev;
}

void *moep_dev_get_priv(moep_dev_t dev, struct moep_dev_ops *ops)
{
	assert_module(dev, ops, NULL);

	return dev->priv;
}

int moep_dev_get_tx_event(moep_dev_t dev)
{
	return dev->tx_event;
}

int moep_dev_get_rx_event(moep_dev_t dev)
{
	return dev->rx_event;
}

int moep_dev_set_rx_event(moep_dev_t dev, int event)
{
	int old;

	old = dev->rx_event;
	dev->rx_event = event;
	return old;
}

void moep_dev_pair(moep_dev_t dev1, moep_dev_t dev2)
{
	moep_dev_set_rx_event(dev1, moep_dev_get_tx_event(dev2));
	moep_dev_set_rx_event(dev2, moep_dev_get_tx_event(dev1));
}

static int queue_frame(moep_dev_t dev, struct frame *f)
{
	u64 event;
	int ret;

	do {
		ret = read(dev->tx_event, &event, 8);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		// TODO maybe always ?
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			free(f->data);
			free(f);
			return -1;
		}
	}

	list_add_tail(&f->list, &dev->frame_queue);

	return 0;
}

rx_handler moep_dev_get_rx_handler(moep_dev_t dev)
{
	return dev->rx;
}

rx_handler moep_dev_set_rx_handler(moep_dev_t dev, rx_handler handler)
{
	rx_handler old;

	old = dev->rx;
	dev->rx = handler;
	return old;
}

int moep_dev_tx(moep_dev_t dev, moep_frame_t frame)
{
	struct frame *f;

	if (!(f = malloc(sizeof(*f)))) {
		errno = ENOMEM;
		return -1;
	}

	f->data = NULL;
	if ((f->len = moep_frame_encode(frame, &f->data, dev->mtu)) < 0) {
		free(f);
		return -1;
	}

	return queue_frame(dev, f);
}

rx_raw_handler moep_dev_get_rx_raw_handler(moep_dev_t dev)
{
	return dev->rx_raw;
}

rx_raw_handler moep_dev_set_rx_raw_handler(moep_dev_t dev,
					   rx_raw_handler handler)
{
	rx_raw_handler old;

	old = dev->rx_raw;
	dev->rx_raw = handler;
	return old;
}

int moep_dev_tx_raw(moep_dev_t dev, u8 *buf, size_t buflen)
{
	struct frame *f;

	if (buflen > dev->mtu) {
		errno = EMSGSIZE;
		return -1;
	}

	if (!(f = malloc(sizeof(*f)))) {
		errno = ENOMEM;
		return -1;
	}
	if (!(f->data = malloc(buflen))) {
		free(f);
		errno = ENOMEM;
		return -1;
	}

	memcpy(f->data, buf, buflen);
	f->len = buflen;

	return queue_frame(dev, f);
}

moep_frame_t moep_dev_frame_create(moep_dev_t dev)
{
	return moep_frame_create(&dev->l1_ops, &dev->l2_ops);
}

moep_frame_t moep_dev_frame_decode(moep_dev_t dev, u8 *buf, size_t buflen)
{
	moep_frame_t frame;

	if (!(frame = moep_dev_frame_create(dev)))
		return NULL;
	if (moep_frame_decode(frame, buf, buflen)) {
		moep_frame_destroy(frame);
		return NULL;
	}
	return frame;
}

void moep_dev_frame_convert(moep_dev_t dev, moep_frame_t frame)
{
	moep_frame_convert(frame, &dev->l1_ops, &dev->l2_ops);
}

void moep_dev_close(moep_dev_t dev)
{
	struct frame *f, *tmp;

	list_for_each_entry_safe(f, tmp, &dev->frame_queue, list) {
		list_del(&f->list);
		free(f);
	}
	list_del(&dev->list);
	close(dev->tx_event);
	if (dev->ops.close)
		dev->ops.close(dev->fd, dev->priv);
	free(dev);
}
