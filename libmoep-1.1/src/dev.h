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

#ifndef DEV_H
#define DEV_H

#include <moep80211/frame.h>
#include <moep80211/dev.h>
#include <moep80211/module.h>

#include "list.h"


struct moep_dev {
	struct list_head list;
	int fd;
	int mtu;
	struct moep_dev_ops ops;
	void *priv;
	struct moep_frame_ops l1_ops;
	struct moep_frame_ops l2_ops;
	struct list_head frame_queue;
	int tx_event;
	int rx_event;
	rx_handler rx;
	rx_raw_handler rx_raw;
};

struct frame {
	struct list_head list;
	u8 *data;
	int len;
};


extern struct list_head moep_dev_list;

#endif /* DEV_H */
