/*
    wificurse - WiFi Jamming tool
    Copyright (C) 2012  oblique

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/wireless.h>
#include "error.h"
#include "iw.h"


void iw_init_dev(struct iw_dev *dev) {
	memset(dev, 0, sizeof(*dev));
	dev->fd_in = -1;
	dev->fd_out = -1;
}

/* man 7 netdevice
 * man 7 packet
 */
int iw_open(struct iw_dev *dev) {
	struct ifreq ifr;
	struct iwreq iwr;
	struct sockaddr_ll sll;
	struct packet_mreq mreq;
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return_error("socket");
	dev->fd_in = fd;

	dev->fd_out = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (dev->fd_out < 0)
		return_error("socket");

	/* save current interface flags */
	memset(&dev->old_flags, 0, sizeof(dev->old_flags));
	strncpy(dev->old_flags.ifr_name, dev->ifname, sizeof(dev->old_flags.ifr_name)-1);
	if (ioctl(fd, SIOCGIFFLAGS, &dev->old_flags) < 0) {
		dev->old_flags.ifr_name[0] = '\0';
		return_error("ioctl(SIOCGIFFLAGS)");
	}

	/* save current interface mode */
	memset(&dev->old_mode, 0, sizeof(dev->old_mode));
	strncpy(dev->old_mode.ifr_name, dev->ifname, sizeof(dev->old_mode.ifr_name)-1);
	if (ioctl(fd, SIOCGIWMODE, &dev->old_mode) < 0) {
		dev->old_mode.ifr_name[0] = '\0';
		return_error("ioctl(SIOCGIWMODE)");
	}

	/* set interface down (ifr_flags = 0) */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* set monitor mode */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev->ifname, sizeof(iwr.ifr_name)-1);
	iwr.u.mode = IW_MODE_MONITOR;
	if (ioctl(fd, SIOCSIWMODE, &iwr) < 0)
		return_error("ioctl(SIOCSIWMODE)");

	/* set interface up, broadcast and running */
	ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* get interface index */
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		return_error("ioctl(SIOCGIFINDEX)");
	dev->ifindex = ifr.ifr_ifindex;

	/* bind interface to fd_in socket */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = dev->ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(dev->fd_in, (struct sockaddr*)&sll, sizeof(sll)) < 0)
		return_error("bind(%s)", dev->ifname);

	/* bind interface to fd_out socket */
	if (bind(dev->fd_out, (struct sockaddr*)&sll, sizeof(sll)) < 0)
		return_error("bind(%s)", dev->ifname);

	shutdown(dev->fd_in, SHUT_WR);
	shutdown(dev->fd_out, SHUT_RD);

	/* set fd_in in promiscuous mode */
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = dev->ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(dev->fd_in, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		return_error("setsockopt(PACKET_MR_PROMISC)");

	return 0;
}

void iw_close(struct iw_dev *dev) {
	struct ifreq ifr;

	if (dev->fd_in == -1)
		return;

	if (dev->fd_out == -1) {
		close(dev->fd_in);
		return;
	}

	if (dev->old_flags.ifr_name[0] != '\0') {
		/* set interface down (ifr_flags = 0) */
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
		ioctl(dev->fd_in, SIOCSIFFLAGS, &ifr);
		/* restore old mode */
		if (dev->old_mode.ifr_name[0] != '\0')
			ioctl(dev->fd_in, SIOCSIWMODE, &dev->old_mode);
		/* restore old flags */
		ioctl(dev->fd_in, SIOCSIFFLAGS, &dev->old_flags);
	}

	close(dev->fd_in);
	close(dev->fd_out);
}

ssize_t iw_write(struct iw_dev *dev, void *buf, size_t count) {
	unsigned char *pbuf, *pkt;
	struct radiotap_hdr *rt_hdr;
	struct write_radiotap_data *w_rt_data;
	ssize_t r;

	pbuf = malloc(sizeof(*rt_hdr) + sizeof(*w_rt_data) + count);
	if (pbuf == NULL)
		return_error("malloc");

	rt_hdr = (struct radiotap_hdr*)pbuf;
	w_rt_data = (struct write_radiotap_data*)(pbuf + sizeof(*rt_hdr));
	pkt = pbuf + sizeof(*rt_hdr) + sizeof(*w_rt_data);

	/* radiotap header */
	memset(rt_hdr, 0, sizeof(*rt_hdr));
	rt_hdr->len = sizeof(*rt_hdr) + sizeof(*w_rt_data);
	rt_hdr->present = RADIOTAP_F_PRESENT_RATE | RADIOTAP_F_PRESENT_TX_FLAGS;
	/* radiotap fields */
	memset(w_rt_data, 0, sizeof(*w_rt_data));
	w_rt_data->rate = 2; /* 1 Mb/s */
	w_rt_data->tx_flags = RADIOTAP_F_TX_FLAGS_NOACK | RADIOTAP_F_TX_FLAGS_NOSEQ;
	/* packet */
	memcpy(pkt, buf, count);

	r = send(dev->fd_out, pbuf, rt_hdr->len + count, 0);
	if (r < 0) {
		free(pbuf);
		return_error("send");
	} else if (r > 0) {
		r -= rt_hdr->len;
		if (r <= 0)
			r = 0;
	}

	free(pbuf);

	return r;
}

ssize_t iw_read(struct iw_dev *dev, void *buf, size_t count, uint8_t **pkt, size_t *pkt_sz) {
	struct radiotap_hdr *rt_hdr;
	int r;

	*pkt = NULL;
	*pkt_sz = 0;

	/* read packet */
	r = recv(dev->fd_in, buf, count, 0);
	if (r < 0)
		return_error("recv");
	else if (r == 0)
		return 0;

	rt_hdr = buf;
	if (sizeof(*rt_hdr) >= r || rt_hdr->len >= r)
		return ERRNODATA;

	*pkt = buf + rt_hdr->len;
	*pkt_sz = r - rt_hdr->len;

	return r;
}

int iw_set_channel(struct iw_dev *dev, int chan) {
	struct iwreq iwr;

	/* set channel */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev->ifname, sizeof(iwr.ifr_name)-1);
	iwr.u.freq.flags = IW_FREQ_FIXED;
	iwr.u.freq.m = chan;
	if (ioctl(dev->fd_in, SIOCSIWFREQ, &iwr) < 0)
		return_error("ioctl(SIOCSIWFREQ)");
	dev->chan = chan;

	return 0;
}
