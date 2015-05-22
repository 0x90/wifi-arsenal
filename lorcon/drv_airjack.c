/*
    This file is part of lorcon

    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <fcntl.h>

#include "ajinject.h"
#include "tx80211.h"
#include "tx80211_packet.h"

int tx80211_airjack_init(struct tx80211 *in_tx)
{

	in_tx->capabilities = tx80211_airjack_capabilities();
	in_tx->open_callthrough = &ajinj_open;
	in_tx->close_callthrough = &ajinj_close;
	in_tx->setmode_callthrough = &ajinj_setmode;
	in_tx->getmode_callthrough = &ajinj_getmode;
	in_tx->getchan_callthrough = &ajinj_getchannel;
	in_tx->setchan_callthrough = &ajinj_setchannel;
	in_tx->txpacket_callthrough = &ajinj_send;
	in_tx->setfuncmode_callthrough = NULL;

	return 0;
}

int tx80211_airjack_capabilities()
{
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | TX80211_CAP_DSSSTX);
}

/* A few function wrappers, standardized to be used as callthroughs, passing
   the appropriate parameters to the aj_set/get functions. */

int ajinj_open(struct tx80211 *ajinj)
{
	return (ajinj->raw_fd = aj_getsocket(ajinj->ifname));
}

int ajinj_close(struct tx80211 *ajinj)
{
	return (close(ajinj->raw_fd));
}

int ajinj_setchannel(struct tx80211 *ajinj, int channel)
{
	return (aj_setchannel(ajinj->ifname, channel));
}

int ajinj_setmode(struct tx80211 *ajinj, int mode)
{
	return (aj_setmode(ajinj->ifname, mode));
}

int ajinj_getmode(struct tx80211 *ajinj)
{
	return -1;		/* TODO */
}

int ajinj_getchannel(struct tx80211 *ajinj)
{
	return -1;		/* TODO */
}

int ajinj_send(struct tx80211 *ajinj, struct tx80211_packet *in_pkt)
{
	return (aj_xmitframe(ajinj->ifname, in_pkt->packet, in_pkt->plen,
			ajinj->errstr));
}

/* End wrapper functions */

/* aj_getnonblock accepts the airjack_data structure with an open socket, and
   returns whether the interface is currently in blocking (0) or nonblock (1)
   mode. */
int aj_getnonblock(char *ifname)
{

	int flags, mode, sock;

	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}

	flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0) {
		close(sock);
		return (-1);
	}

	mode = flags & O_NONBLOCK;
	close(sock);
	return (mode);

}

/* aj_setmonitor sets or disables RFMON mode for AirJack interfaces */
int aj_setmonitor(char *ifname, int rfmonset)
{

	struct aj_config ajconf;
	struct ifreq req;
	int sock;

	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}

	req.ifr_data = (char *)&ajconf;
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	/* populate the structure */
	if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	ajconf.monitor = rfmonset;

	if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	return (0);

}

/* aj_setmode sets the operating mode for  AirJack interfaces */
int aj_setmode(char *ifname, int mode)
{

	struct aj_config ajconf;
	struct ifreq req;
	int sock;

	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}

	req.ifr_data = (char *)&ajconf;
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	/* populate the structure */
	if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	ajconf.mode = mode;

	if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	close(sock);
	return (0);

}

/* aj_setchannel changes the airjack card to the specified channel */
int aj_setchannel(char *ifname, int channel)
{

	struct aj_config ajconf;
	struct ifreq req;
	int sock;

	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}

	req.ifr_data = (char *)&ajconf;
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	/* populate the structure */
	if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	ajconf.channel = channel;

	if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	close(sock);
	return (0);

}

int aj_setessid(char *ifname, char *essid, int len)
{

	struct aj_config ajconf;
	struct ifreq req;
	int sock;

	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}

	req.ifr_data = (char *)&ajconf;
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	/* populate the structure */
	if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	strncpy((char *)ajconf.essid+1, essid, len);
	ajconf.essid[0] = len;

	if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	close(sock);
	return (0);
}

int aj_setmac(char *ifname, uint8_t *mac)
{

	struct aj_config ajconf;
	struct ifreq req;
	int sock;

	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}

	req.ifr_data = (char *)&ajconf;
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	/* populate the structure */
	if (ioctl(sock, SIOCAJGMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	memcpy(ajconf.ownmac, mac, 6);

	if (ioctl(sock, SIOCAJSMODE, &req) < 0) {
		close(sock);
		return (-1);
	}

	close(sock);
	return (0);
}

/* aj_xmitframe accepts a 8-bit array of data, and a number of bytes to send
   with an open socket.  If we are blocking on the socket, just transmit the
   data and return 0 is send returns the same number of bytes sent.  If we are
   in nonblock mode, perform a select on the socket and if it is available for
   writing, send the data.  If it is not available for writing, we loop and 
   keep trying to send until select returns the socket as available.  Note that
   this behavior is different from the aj_recvframe function that will
   immediately return of select indicates that the socket is not ready to
   deliver a frame. */
int aj_xmitframe(char *ifname, uint8_t *xmit, int len, char *errstr)
{

	int xmitlen = 0;
	int n = 0, sock;
	struct timeval tv;
	fd_set saved_set, wset;

	if ((sock = aj_getsocket(ifname)) < 0) {
		close(sock);
		return (-1);
	}

	if (aj_getnonblock(ifname) == 0) {

		/* We are blocking, just transmit the data */
		xmitlen = write(sock, &xmit, len);

	} else {
		/* We are nonblock, perform a select on the socket */

		FD_ZERO(&saved_set);
		FD_SET(sock, &saved_set);
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		while (1) {

			wset = saved_set;
			n = select(sock + 1, NULL, &wset, NULL, &tv);
			if (n < 0) {
				if (errno == EINTR || errno == EAGAIN) {
					continue;
				} else {
					snprintf(errstr, TX80211_STATUS_MAX,
						"select on write socket "
						"returned %d: %s.\n", errno,
						strerror(errno));
					return TX80211_ENOTX;
				}
			} else if (n == 0) {
				/* timeout expired before a filehandle was 
				   populated.  try again. */
				continue;
			} else {
				printf("select returned %d.\n", n);
				/* select returned > 0, transmit the packet */
				printf("before send errno: %d\n", errno);
				xmitlen = write(sock, &xmit, len);
				printf("after send errno: %d\n", errno);
				printf("send returned %d.\n", xmitlen);
				break;
			}

		}		/* end while(1) */

	}

	close(sock);
	if (len == xmitlen) {
		return (0);
	} else {
		snprintf(errstr, TX80211_STATUS_MAX, "send returned %d, not %d "
				"bytes: %s", xmitlen, len, strerror(errno));
		return TX80211_ENOTX;
	}

}

/* aj_getsocket accepts the AirJack interface char * and 
   return a socket, or -1 on error.  This is cribbed right from essid_jack.c,
   thanks Abaddon. */
int aj_getsocket(char *ifname)
{

	struct sockaddr_ll addr;
	struct ifreq req;
	struct aj_config aj_conf;
	int sock;

	/* open the link layer socket */
	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		return (-1);
	}

	/* get the interface index */
	memset(&req, 0, sizeof(struct ifreq));
	memset(&aj_conf, 0, sizeof(struct aj_config));
	strcpy(req.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFINDEX, &req) < 0) {
		close(sock);
		return (-1);
	}

	/* bind the socket to the interface */
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_ifindex = req.ifr_ifindex;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_family = AF_PACKET;
	if (bind(sock, (struct sockaddr *)&addr, 
			sizeof(struct sockaddr_ll)) < 0) {
		close(sock);
		return (-1);
	}

	return (sock);
}

#endif /* linux */
