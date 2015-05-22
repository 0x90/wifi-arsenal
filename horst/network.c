/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include "main.h"
#include "util.h"
#include "channel.h"
#include "network.h"


extern struct config conf;

int srv_fd = -1;
int cli_fd = -1;
static int netmon_fd;

#define PROTO_VERSION	2


enum pkt_type {
	PROTO_PKT_INFO		= 0,
	PROTO_CHAN_LIST		= 1,
	PROTO_CONF_CHAN		= 2,
	PROTO_CONF_FILTER	= 3,
};


struct net_header {
	unsigned char version;
	unsigned char type;
} __attribute__ ((packed));


struct net_conf_chan {
	struct net_header	proto;

	unsigned char do_change;
	unsigned char upper;
	char channel;
	int dwell_time;

} __attribute__ ((packed));


struct net_conf_filter {
	struct net_header	proto;

	unsigned char	filtermac[MAX_FILTERMAC][MAC_LEN];
	char		filtermac_enabled[MAX_FILTERMAC];
	unsigned char	filterbssid[MAC_LEN];
	int		filter_pkt;
	int		filter_mode;
	unsigned char	filter_off;
} __attribute__ ((packed));


struct net_chan_freq {
	unsigned char chan;
	unsigned int freq;
} __attribute__ ((packed));

struct net_chan_list {
	struct net_header	proto;

	unsigned char num_channels;
	struct net_chan_freq channel[1];
} __attribute__ ((packed));


#define PKT_INFO_VERSION	1

struct net_packet_info {
	struct net_header	proto;

	unsigned char		version;

	/* general */
	unsigned int		pkt_types;	/* bitmask of packet types */

	/* wlan phy (from radiotap) */
	int			phy_signal;	/* signal strength (usually dBm) */
	int			phy_noise;	/* noise level (always 0) */
	unsigned int		phy_snr;	/* signal to noise ratio (always 0, redundant!) */
	unsigned int		phy_rate;	/* physical rate * 10 (= in 100kbps) */
	unsigned int		phy_freq;	/* frequency */
	unsigned int		phy_flags;	/* A, B, G, shortpre */

	/* wlan mac */
	unsigned int		wlan_len;	/* packet length */
	unsigned int		wlan_type;	/* frame control field */
	unsigned char		wlan_src[MAC_LEN];
	unsigned char		wlan_dst[MAC_LEN];
	unsigned char		wlan_bssid[MAC_LEN];
	char			wlan_essid[WLAN_MAX_SSID_LEN];
	u_int64_t		wlan_tsf;	/* timestamp from beacon */
	unsigned int		wlan_bintval;	/* beacon interval */
	unsigned int		wlan_mode;	/* AP, STA or IBSS */
	unsigned char		wlan_channel;	/* channel from beacon, probe */
	unsigned char		wlan_qos_class;	/* for QDATA frames */
	unsigned int		wlan_nav;	/* frame NAV duration */
	unsigned int		wlan_seqno;	/* sequence number */

#define PKT_WLAN_FLAG_WEP	0x1
#define PKT_WLAN_FLAG_RETRY	0x2
#define PKT_WLAN_FLAG_WPA	0x4
#define PKT_WLAN_FLAG_RSN	0x8

	/* bitfields are not portable - endianness is not guaranteed */
	unsigned int		wlan_flags;

	/* IP */
	unsigned int		ip_src;
	unsigned int		ip_dst;
	unsigned int		tcpudp_port;
	unsigned int		olsr_type;
	unsigned int		olsr_neigh;
	unsigned int		olsr_tc;

#define PKT_BAT_FLAG_GW		0x1
	unsigned char		bat_flags;
	unsigned char		bat_pkt_type;

	unsigned char		phy_rate_idx;
	unsigned char		phy_rate_flags;
} __attribute__ ((packed));


static int
net_write(int fd, unsigned char* buf, size_t len)
{
	int ret;
	ret = write(fd, buf, len);
	if (ret == -1) {
		if (errno == EPIPE) {
			printlog("Client has closed");
			close(fd);
			if (fd == cli_fd)
				cli_fd = -1;
			net_init_server_socket(conf.port);
		}
		else
			printlog("ERROR: in net_write");
		return 0;
	}
	return 1;
}


int
net_send_packet(struct packet_info *p)
{
	struct net_packet_info np;

	np.proto.version = PROTO_VERSION;
	np.proto.type	= PROTO_PKT_INFO;

	np.version	= PKT_INFO_VERSION;
	np.pkt_types	= htole32(p->pkt_types);
	np.phy_signal	= htole32(p->phy_signal);
	np.phy_noise	= htole32(0);
	np.phy_snr	= htole32(0);
	np.phy_rate	= htole32(p->phy_rate);
	np.phy_rate_idx	= p->phy_rate_idx;
	np.phy_rate_flags = p->phy_rate_flags;
	np.phy_freq	= htole32(p->phy_freq);
	np.phy_flags	= htole32(p->phy_flags);
	np.wlan_len	= htole32(p->wlan_len);
	np.wlan_type	= htole32(p->wlan_type);
	memcpy(np.wlan_src, p->wlan_src, MAC_LEN);
	memcpy(np.wlan_dst, p->wlan_dst, MAC_LEN);
	memcpy(np.wlan_bssid, p->wlan_bssid, MAC_LEN);
	memcpy(np.wlan_essid, p->wlan_essid, WLAN_MAX_SSID_LEN);
	np.wlan_tsf	= htole64(p->wlan_tsf);
	np.wlan_bintval	= htole32(p->wlan_bintval);
	np.wlan_mode	= htole32(p->wlan_mode);
	np.wlan_channel = p->wlan_channel;
	np.wlan_qos_class = p->wlan_qos_class;
	np.wlan_nav	= htole32(p->wlan_nav);
	np.wlan_seqno	= htole32(p->wlan_seqno);
	np.wlan_flags = 0;
	if (p->wlan_wep)
		np.wlan_flags |= PKT_WLAN_FLAG_WEP;
	if (p->wlan_retry)
		np.wlan_flags |= PKT_WLAN_FLAG_RETRY;
	if (p->wlan_wpa)
		np.wlan_flags |= PKT_WLAN_FLAG_WPA;
	if (p->wlan_rsn)
		np.wlan_flags |= PKT_WLAN_FLAG_RSN;
	np.wlan_flags	= htole32(np.wlan_flags);
	np.ip_src	= p->ip_src;
	np.ip_dst	= p->ip_dst;
	np.tcpudp_port	= htole32(p->tcpudp_port);
	np.olsr_type	= htole32(p->olsr_type);
	np.olsr_neigh	= htole32(p->olsr_neigh);
	np.olsr_tc	= htole32(p->olsr_tc);
	np.bat_flags = 0;
	if (p->bat_gw)
		np.bat_flags |= PKT_BAT_FLAG_GW;
	np.bat_pkt_type = p->bat_packet_type;

	net_write(cli_fd, (unsigned char *)&np, sizeof(np));
	return 0;
}


static int
net_receive_packet(unsigned char *buffer, size_t len)
{
	struct net_packet_info *np;
	struct packet_info p;

	if (len < sizeof(struct net_packet_info))
		return 0;

	np = (struct net_packet_info *)buffer;

	if (np->phy_rate == 0)
		return 0;

	if (np->version != PKT_INFO_VERSION)
		return 0;

	memset(&p, 0, sizeof(p));
	p.pkt_types	= le32toh(np->pkt_types);
	p.phy_signal	= le32toh(np->phy_signal);
	p.phy_rate	= le32toh(np->phy_rate);
	p.phy_rate_idx	= np->phy_rate_idx;
	p.phy_rate_flags= np->phy_rate_flags;
	p.phy_freq	= le32toh(np->phy_freq);
	p.phy_flags	= le32toh(np->phy_flags);
	p.wlan_len	= le32toh(np->wlan_len);
	p.wlan_type	= le32toh(np->wlan_type);
	memcpy(p.wlan_src, np->wlan_src, MAC_LEN);
	memcpy(p.wlan_dst, np->wlan_dst, MAC_LEN);
	memcpy(p.wlan_bssid, np->wlan_bssid, MAC_LEN);
	memcpy(p.wlan_essid, np->wlan_essid, WLAN_MAX_SSID_LEN);
	p.wlan_tsf	= le64toh(np->wlan_tsf);
	p.wlan_bintval	= le32toh(np->wlan_bintval);
	p.wlan_mode	= le32toh(np->wlan_mode);
	p.wlan_channel = np->wlan_channel;
	p.wlan_qos_class = np->wlan_qos_class;
	p.wlan_nav	= le32toh(np->wlan_nav);
	p.wlan_seqno	= le32toh(np->wlan_seqno);
	np->wlan_flags	= le32toh(np->wlan_flags);
	if (np->wlan_flags & PKT_WLAN_FLAG_WEP)
		p.wlan_wep = 1;
	if (np->wlan_flags & PKT_WLAN_FLAG_RETRY)
		p.wlan_retry = 1;
	if (np->wlan_flags & PKT_WLAN_FLAG_WPA)
		p.wlan_wpa = 1;
	if (np->wlan_flags & PKT_WLAN_FLAG_RSN)
		p.wlan_rsn = 1;
	p.ip_src	= np->ip_src;
	p.ip_dst	= np->ip_dst;
	p.tcpudp_port	= le32toh(np->tcpudp_port);
	p.olsr_type	= le32toh(np->olsr_type);
	p.olsr_neigh	= le32toh(np->olsr_neigh);
	p.olsr_tc	= le32toh(np->olsr_tc);
	if (np->bat_flags & PKT_BAT_FLAG_GW)
		p.bat_gw = 1;
	p.bat_packet_type = np->bat_pkt_type;

	handle_packet(&p);

	return sizeof(struct net_packet_info);
}


static void
net_send_conf_chan(int fd)
{
	struct net_conf_chan nc;

	nc.proto.version = PROTO_VERSION;
	nc.proto.type	= PROTO_CONF_CHAN;
	nc.do_change = conf.do_change_channel;
	nc.upper = conf.channel_max;
	nc.channel = conf.channel_idx;
	nc.dwell_time = htole32(conf.channel_time);

	net_write(fd, (unsigned char *)&nc, sizeof(nc));
}


static int
net_receive_conf_chan(unsigned char *buffer, size_t len)
{
	struct net_conf_chan *nc;

	if (len < sizeof(struct net_conf_chan))
		return 0;

	nc = (struct net_conf_chan *)buffer;
	conf.do_change_channel = nc->do_change;
	conf.channel_max = nc->upper;
	conf.channel_time = le32toh(nc->dwell_time);

	if (cli_fd > -1 && nc->channel != conf.channel_idx) /* server */
		channel_change(nc->channel);
	else { /* client */
		conf.channel_idx = nc->channel;
		update_spectrum_durations();
	}

	return sizeof(struct net_conf_chan);
}


static int
net_send_conf_filter(int fd)
{
	struct net_conf_filter nc;
	int i;

	nc.proto.version = PROTO_VERSION;
	nc.proto.type = PROTO_CONF_FILTER;

	for (i = 0; i < MAX_FILTERMAC; i++) {
		memcpy(nc.filtermac[i], conf.filtermac[i], MAC_LEN);
		nc.filtermac_enabled[i] = conf.filtermac_enabled[i];
	}
	memcpy(nc.filterbssid, conf.filterbssid, MAC_LEN);
	nc.filter_pkt = htole32(conf.filter_pkt);
	nc.filter_mode = htole32(conf.filter_mode);
	nc.filter_off = conf.filter_off;

	net_write(fd, (unsigned char *)&nc, sizeof(nc));
	return 0;
}


static int
net_receive_conf_filter(unsigned char *buffer, size_t len)
{
	struct net_conf_filter *nc;
	int i;

	if (len < sizeof(struct net_conf_filter))
		return 0;

	nc = (struct net_conf_filter *)buffer;

	for (i = 0; i < MAX_FILTERMAC; i++) {
		memcpy(conf.filtermac[i], nc->filtermac[i], MAC_LEN);
		conf.filtermac_enabled[i] = nc->filtermac_enabled[i];
	}
	memcpy(conf.filterbssid, nc->filterbssid, MAC_LEN);
	conf.filter_pkt = le32toh(nc->filter_pkt);
	conf.filter_mode = le32toh(nc->filter_mode);
	conf.filter_off = nc->filter_off;

	return sizeof(struct net_conf_filter);
}


static int
net_send_chan_list(int fd)
{
	char* buf;
	struct net_chan_list *nc;
	int i;

	buf = malloc(sizeof(struct net_chan_list) + sizeof(struct net_chan_freq)*(conf.num_channels - 1));
	if (buf == NULL)
		return 0;

	nc = (struct net_chan_list *)buf;
	nc->proto.version = PROTO_VERSION;
	nc->proto.type	= PROTO_CHAN_LIST;

	for (i = 0; i < conf.num_channels && i < MAX_CHANNELS; i++) {
		struct chan_freq* cf = channel_get_struct(i);
		if (cf != NULL) {
			nc->channel[i].chan = cf->chan;
			nc->channel[i].freq = htole32(cf->freq);
			DEBUG("NET send chan %d %d %d\n", i, cf->chan, cf->freq);
		} else {
			printlog("NET send chan ERR");
		}
	}
	nc->num_channels = i;

	net_write(fd, (unsigned char *)buf, sizeof(struct net_chan_list) + sizeof(struct net_chan_freq)*(i - 1));
	free(buf);
	return 0;
}


static int
net_receive_chan_list(unsigned char *buffer, size_t len)
{
	struct net_chan_list *nc;
	int i;

	if (len < sizeof(struct net_chan_list))
		return 0;

	nc = (struct net_chan_list *)buffer;

	if (len < sizeof(struct net_chan_list) + sizeof(struct net_chan_freq)*(nc->num_channels - 1))
		return 0;

	if (nc->num_channels > MAX_CHANNELS) {
		printlog("ERR: server sent too many channels, truncated");
		conf.num_channels = MAX_CHANNELS;
	} else {
		conf.num_channels = nc->num_channels;
	}

	for (i = 0; i < conf.num_channels; i++) {
		channel_set(i, nc->channel[i].chan, le32toh(nc->channel[i].freq));
		DEBUG("NET recv chan %d %d %d\n", i, nc->channel[i].chan, le32toh(nc->channel[i].freq));
	}
	init_spectrum();
	return sizeof(struct net_chan_list) + sizeof(struct net_chan_freq)*(nc->num_channels - 1);
}


static int
try_receive_packet(unsigned char* buf, size_t len)
{
	struct net_header *nh = (struct net_header *)buf;

	if (nh->version != PROTO_VERSION) {
		printlog("ERROR: protocol version %x", nh->version);
		return 0;
	}

	switch (nh->type) {
	case PROTO_PKT_INFO:
		len = net_receive_packet(buf, len);
		break;
	case PROTO_CHAN_LIST:
		len = net_receive_chan_list(buf, len);
		break;
	case PROTO_CONF_CHAN:
		len = net_receive_conf_chan(buf, len);
		break;
	case PROTO_CONF_FILTER:
		len = net_receive_conf_filter(buf, len);
		break;
	default:
		printlog("ERROR: unknown net packet type");
		len = 0;
	}

	return len; /* the number of bytes we have consumed */
}


int
net_receive(int fd, unsigned char* buffer, size_t* buflen, size_t maxlen)
{
	int len, consumed = 0;

	len = recv(fd, buffer + *buflen, maxlen - *buflen, MSG_DONTWAIT);

	if (len < 0)
		return 0;

	*buflen += len;

	while (*buflen > sizeof(struct net_header)) {
		len = try_receive_packet(buffer + consumed, *buflen);
		if (len == 0)
			break;
		*buflen -= len;
		consumed += len;
	}
	memmove(buffer, buffer + consumed, *buflen);

	return consumed;
}


int net_handle_server_conn( void )
{
	struct sockaddr_in cin;
	socklen_t cinlen;

	cinlen = sizeof(cin);
	memset(&cin, 0, sizeof(struct sockaddr_in));
	cli_fd = accept(srv_fd, (struct sockaddr*)&cin, &cinlen);

	printlog("Accepting client");

	/* send initial config */
	net_send_chan_list(cli_fd);
	net_send_conf_chan(cli_fd);
	net_send_conf_filter(cli_fd);

	/* we only accept one client, so close server socket */
	close(srv_fd);
	srv_fd = -1;

	return 0;
}


void
net_init_server_socket(int rport)
{
	struct sockaddr_in sock_in;
	int reuse = 1;

	printlog("Initializing server port %d", rport);

	memset(&sock_in, 0, sizeof(struct sockaddr_in));
	sock_in.sin_family = AF_INET;
	sock_in.sin_addr.s_addr = htonl(INADDR_ANY);
	sock_in.sin_port = htons(rport);

	if ((srv_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		err(1, "Could not open server socket");

	if (setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
		err(1, "setsockopt SO_REUSEADDR");

	if (bind(srv_fd, (struct sockaddr*)&sock_in, sizeof(sock_in)) < 0)
		err(1, "bind");

	if (listen(srv_fd, 0) < 0)
		err(1, "listen");
}


int
net_open_client_socket(char* serveraddr, int rport)
{
	struct addrinfo saddr;
	struct addrinfo *result, *rp;
	char rport_str[20];
	int ret;

	snprintf(rport_str, 20, "%d", rport);

	printlog("Connecting to server %s port %s", serveraddr, rport_str);

	/* Obtain address(es) matching host/port */
	memset(&saddr, 0, sizeof(struct addrinfo));
	saddr.ai_family = AF_INET;
	saddr.ai_socktype = SOCK_STREAM;
	saddr.ai_flags = 0;
	saddr.ai_protocol = 0;

	ret = getaddrinfo(serveraddr, rport_str, &saddr, &result);
	if (ret != 0) {
		fprintf(stderr, "Could not resolve: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	/* getaddrinfo() returns a list of address structures.
	 * Try each address until we successfully connect. */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		netmon_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (netmon_fd == -1)
			continue;

		if (connect(netmon_fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; /* Success */

		close(netmon_fd);
	}

	if (rp == NULL) {
		/* No address succeeded */
		freeaddrinfo(result);
		err(1, "Could not connect");
	}

	freeaddrinfo(result);

	printlog("Connected to server %s", serveraddr);
	return netmon_fd;
}


void
net_finish(void) {
	if (srv_fd != -1)
		close(srv_fd);

	if (cli_fd != -1)
		close(cli_fd);

	if (netmon_fd)
		close(netmon_fd);
}


void
net_send_channel_config(void)
{
	if (conf.serveraddr[0] != '\0')
		net_send_conf_chan(netmon_fd);
	else if (conf.allow_client && cli_fd > -1)
		net_send_conf_chan(cli_fd);
}


void
net_send_filter_config(void)
{
	if (conf.serveraddr[0] != '\0')
		net_send_conf_filter(netmon_fd);
	else if (conf.allow_client && cli_fd > -1)
		net_send_conf_filter(cli_fd);
}
