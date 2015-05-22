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
#include <signal.h>
#include <sys/time.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>

#include "main.h"
#include "util.h"
#include "capture.h"
#include "protocol_parser.h"
#include "network.h"
#include "display.h"
#include "wlan_util.h"
#include "ieee80211_util.h"
#include "control.h"
#include "channel.h"
#include "node.h"
#include "essid.h"
#include "conf_options.h"


struct list_head nodes;
struct essid_meta_info essids;
struct history hist;
struct statistics stats;
struct channel_info spectrum[MAX_CHANNELS];
struct node_names_info node_names;

struct config conf;

struct timeval the_time;

int mon; /* monitoring socket */

static FILE* DF = NULL;

/* receive packet buffer
 *
 * due to the way we receive packets the network (TCP connection) we have to
 * expect the reception of partial packet as well as the reception of several
 * packets at one. thus we implement a buffered receive where partially received
 * data stays in the buffer.
 *
 * we need two buffers: one for packet capture or receiving from the server and
 * another one for data the clients sends to the server.
 *
 * not sure if this is also an issue with local packet capture, but it is not
 * implemented there.
 *
 * size: max 80211 frame (2312) + space for prism2 header (144)
 * or radiotap header (usually only 26) + some extra */
static unsigned char buffer[2312 + 200];
static size_t buflen;

/* for packets from client to server */
static unsigned char cli_buffer[500];
static size_t cli_buflen;

/* for select */
static fd_set read_fds;
static fd_set write_fds;
static fd_set excpt_fds;
static struct timeval tv;


void __attribute__ ((format (printf, 1, 2)))
printlog(const char *fmt, ...)
{
	char buf[128];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(&buf[1], 127, fmt, ap);
	va_end(ap);

	if (conf.quiet || conf.debug || !conf.display_initialized)
		printf("%s\n", &buf[1]);
	else {
		/* fix up string for display log */
		buf[0] = '\n';
		display_log(buf);
	}
}


static void
update_history(struct packet_info* p)
{
	if (p->phy_signal == 0)
		return;

	hist.signal[hist.index] = p->phy_signal;
	hist.rate[hist.index] = p->phy_rate;
	hist.type[hist.index] = (p->phy_flags & PHY_FLAG_BADFCS) ? 1 : p->wlan_type;
	hist.retry[hist.index] = p->wlan_retry;

	hist.index++;
	if (hist.index == MAX_HISTORY)
		hist.index = 0;
}


static void
update_statistics(struct packet_info* p)
{
	int type = (p->phy_flags & PHY_FLAG_BADFCS) ? 1 : p->wlan_type;

	if (p->phy_rate_idx == 0)
		return;

	stats.packets++;
	stats.bytes += p->wlan_len;
	if (p->wlan_retry)
		stats.retries++;

	if (p->phy_rate_idx > 0 && p->phy_rate_idx < MAX_RATES) {
		stats.duration += p->pkt_duration;
		stats.packets_per_rate[p->phy_rate_idx]++;
		stats.bytes_per_rate[p->phy_rate_idx] += p->wlan_len;
		stats.duration_per_rate[p->phy_rate_idx] += p->pkt_duration;
	}

	if (type >= 0 && type < MAX_FSTYPE) {
		stats.packets_per_type[type]++;
		stats.bytes_per_type[type] += p->wlan_len;
		if (p->phy_rate_idx > 0 && p->phy_rate_idx < MAX_RATES)
			stats.duration_per_type[type] += p->pkt_duration;
	}
}


static void
update_spectrum(struct packet_info* p, struct node_info* n)
{
	struct channel_info* chan;
	struct chan_node* cn;

	if (p->pkt_chan_idx < 0)
		return; /* chan not found */

	chan = &spectrum[p->pkt_chan_idx];
	chan->signal = p->phy_signal;
	chan->packets++;
	chan->bytes += p->wlan_len;
	chan->durations += p->pkt_duration;
	ewma_add(&chan->signal_avg, -chan->signal);

	if (!n) {
		DEBUG("spec no node\n");
		return;
	}

	/* add node to channel if not already there */
	list_for_each(&chan->nodes, cn, chan_list) {
		if (cn->node == n) {
			DEBUG("SPEC node found %p\n", cn->node);
			break;
		}
	}
	if (cn->node != n) {
		DEBUG("SPEC node adding %p\n", n);
		cn = malloc(sizeof(struct chan_node));
		cn->node = n;
		cn->chan = chan;
		ewma_init(&cn->sig_avg, 1024, 8);
		list_add_tail(&chan->nodes, &cn->chan_list);
		list_add_tail(&n->on_channels, &cn->node_list);
		chan->num_nodes++;
		n->num_on_channels++;
	}
	/* keep signal of this node as seen on this channel */
	cn->sig = p->phy_signal;
	ewma_add(&cn->sig_avg, -cn->sig);
	cn->packets++;
}


void
update_spectrum_durations(void)
{
	/* also if channel was not changed, keep stats only for every channel_time.
	 * display code uses durations_last to get a more stable view */
	if (conf.channel_idx >= 0) {
		spectrum[conf.channel_idx].durations_last =
				spectrum[conf.channel_idx].durations;
		spectrum[conf.channel_idx].durations = 0;
		ewma_add(&spectrum[conf.channel_idx].durations_avg,
			 spectrum[conf.channel_idx].durations_last);
	}
}


static void 
write_to_file(struct packet_info* p)
{
	fprintf(DF, "%s, %s, ",
		get_packet_type_name(p->wlan_type), ether_sprintf(p->wlan_src));
	fprintf(DF, "%s, ", ether_sprintf(p->wlan_dst));
	fprintf(DF, "%s, ", ether_sprintf(p->wlan_bssid));
	fprintf(DF, "%x, %d, %d, %d, %d, %d, %d, ",
		p->pkt_types, p->phy_signal, 0, 0,
		p->wlan_len, p->phy_rate, p->phy_freq);
	fprintf(DF, "%016llx, ", (unsigned long long)p->wlan_tsf);
	fprintf(DF, "%s, %d, %d, %d, %d, %d, ",
		p->wlan_essid, p->wlan_mode, p->wlan_channel,
		p->wlan_wep, p->wlan_wpa, p->wlan_rsn);
	fprintf(DF, "%s, ", ip_sprintf(p->ip_src));
	fprintf(DF, "%s, ", ip_sprintf(p->ip_dst));
	fprintf(DF, "%d, %d\n", p->olsr_type, p->olsr_neigh);
	fflush(DF);
}


/* return 1 if packet is filtered */
static int
filter_packet(struct packet_info* p)
{
	int i;

	if (conf.filter_off)
		return 0;

	if (conf.filter_pkt != PKT_TYPE_ALL && (p->pkt_types & ~conf.filter_pkt)) {
		stats.filtered_packets++;
		return 1;
	}

	/* cannot trust anything if FCS is bad */
	if (p->phy_flags & PHY_FLAG_BADFCS)
		return 0;

	if (conf.filter_mode != WLAN_MODE_ALL && ((p->wlan_mode & ~conf.filter_mode) || p->wlan_mode == 0)) {
		/* this also filters out packets where we cannot associate a mode (ACK, RTS/CTS) */
		stats.filtered_packets++;
		return 1;
	}

	if (MAC_NOT_EMPTY(conf.filterbssid) &&
	    memcmp(p->wlan_bssid, conf.filterbssid, MAC_LEN) != 0) {
		stats.filtered_packets++;
		return 1;
	}

	if (conf.do_macfilter) {
		for (i = 0; i < MAX_FILTERMAC; i++) {
			if (MAC_NOT_EMPTY(p->wlan_src) &&
			    conf.filtermac_enabled[i] &&
			    memcmp(p->wlan_src, conf.filtermac[i], MAC_LEN) == 0) {
				return 0;
			}
		}
		stats.filtered_packets++;
		return 1;
	}
	return 0;
}


void
fixup_packet_channel(struct packet_info* p) {
	int i = -1;

	/* get channel index for packet */
	if (p->phy_freq) {
		i = channel_find_index_from_freq(p->phy_freq);
	}

	/* if not found from pkt, best guess from config but it might be
	 * unknown (-1) too */
	if (i < 0)
		p->pkt_chan_idx = conf.channel_idx;
	else
		p->pkt_chan_idx = i;

	/* wlan_channel is only known for beacons and probe response,
	 * otherwise we set it from the physical channel */
	if (p->wlan_channel == 0 && p->pkt_chan_idx >= 0)
		p->wlan_channel = channel_get_chan_from_idx(p->pkt_chan_idx);

	/* if current channel is unknown (this is a mac80211 bug), guess it from
	 * the packet */
	if (conf.channel_idx < 0 && p->pkt_chan_idx >= 0)
		conf.channel_idx = p->pkt_chan_idx;
}


void
handle_packet(struct packet_info* p)
{
	struct node_info* n = NULL;

	/* filter on server side only */
	if (!conf.serveraddr[0] != '\0' && filter_packet(p)) {
		if (!conf.quiet && !conf.paused && !conf.debug)
			update_display_clock();
		return;
	}

	fixup_packet_channel(p);

	if (cli_fd != -1)
		net_send_packet(p);

	if (conf.dumpfile[0] != '\0' && !conf.paused && DF != NULL)
		write_to_file(p);

	if (conf.paused)
		return;

	DEBUG("handle %s\n", get_packet_type_name(p->wlan_type));

	if (!(p->phy_flags & PHY_FLAG_BADFCS)) {
		/* we can't trust any fields except phy_* of packets with bad FCS,
		 * so we can't do all this here */
		n = node_update(p);

		if (n)
			p->wlan_retries = n->wlan_retries_last;

		p->pkt_duration = ieee80211_frame_duration(
				p->phy_flags & PHY_FLAG_MODE_MASK,
				p->wlan_len, p->phy_rate,
				p->phy_flags & PHY_FLAG_SHORTPRE,
				0 /*shortslot*/, p->wlan_type,
				p->wlan_qos_class,
				p->wlan_retries);
	}

	update_history(p);
	update_statistics(p);
	update_spectrum(p, n);
	update_essids(p, n);

	if (!conf.quiet && !conf.debug)
		update_display(p);
}


static void
local_receive_packet(int fd, unsigned char* buffer, size_t bufsize)
{
	int len;
	struct packet_info p;

	DEBUG("\n===============================================================================\n");

	len = recv_packet(fd, buffer, bufsize);

#if DO_DEBUG
	if (conf.debug) {
		dump_packet(buffer, len);
		DEBUG("\n");
	}
#endif
	memset(&p, 0, sizeof(p));

	if (!parse_packet(buffer, len, &p)) {
		DEBUG("parsing failed\n");
		return;
	}

	handle_packet(&p);
}


static void
receive_any(void)
{
	int ret, mfd;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	FD_ZERO(&excpt_fds);
	if (!conf.quiet && !conf.debug)
		FD_SET(0, &read_fds);
	FD_SET(mon, &read_fds);
	if (srv_fd != -1)
		FD_SET(srv_fd, &read_fds);
	if (cli_fd != -1)
		FD_SET(cli_fd, &read_fds);
	if (ctlpipe != -1)
		FD_SET(ctlpipe, &read_fds);

	tv.tv_sec = 0;
	tv.tv_usec = min(conf.channel_time, 1000000);
	mfd = max(mon, srv_fd);
	mfd = max(mfd, ctlpipe);
	mfd = max(mfd, cli_fd) + 1;

	ret = select(mfd, &read_fds, &write_fds, &excpt_fds, &tv);
	if (ret == -1 && errno == EINTR) /* interrupted */
		return;
	if (ret == 0) { /* timeout */
		if (!conf.quiet && !conf.debug)
			update_display_clock();
		return;
	}
	else if (ret < 0) /* error */
		err(1, "select()");

	/* stdin */
	if (FD_ISSET(0, &read_fds) && !conf.quiet && !conf.debug)
		handle_user_input();

	/* local packet or client */
	if (FD_ISSET(mon, &read_fds)) {
		if (conf.serveraddr[0] != '\0')
			net_receive(mon, buffer, &buflen, sizeof(buffer));
		else
			local_receive_packet(mon, buffer, sizeof(buffer));
	}

	/* server */
	if (srv_fd > -1 && FD_ISSET(srv_fd, &read_fds))
		net_handle_server_conn();

	/* from client to server */
	if (cli_fd > -1 && FD_ISSET(cli_fd, &read_fds))
		net_receive(cli_fd, cli_buffer, &cli_buflen, sizeof(cli_buffer));

	/* named pipe */
	if (ctlpipe > -1 && FD_ISSET(ctlpipe, &read_fds))
		control_receive_command();
}


void
free_lists(void)
{
	int i;
	struct essid_info *e, *f;
	struct node_info *ni, *mi;
	struct chan_node *cn, *cn2;

	/* free node list */
	list_for_each_safe(&nodes, ni, mi, list) {
		DEBUG("free node %s\n", ether_sprintf(ni->last_pkt.wlan_src));
		list_del(&ni->list);
		free(ni);
	}

	/* free essids */
	list_for_each_safe(&essids.list, e, f, list) {
		DEBUG("free essid '%s'\n", e->essid);
		list_del(&e->list);
		free(e);
	}

	/* free channel nodes */
	for (i = 0; i < conf.num_channels; i++) {
		list_for_each_safe(&spectrum[i].nodes, cn, cn2, chan_list) {
			DEBUG("free chan_node %p\n", cn);
			list_del(&cn->chan_list);
			cn->chan->num_nodes--;
			free(cn);
		}
	}
}


static void
finish_all(void)
{
	free_lists();

	if (!conf.serveraddr[0] != '\0')
		close_packet_socket(mon, conf.ifname);

	if (DF != NULL) {
		fclose(DF);
		DF = NULL;
	}

	if (conf.allow_control)
		control_finish();

	if (!conf.debug)
		net_finish();

	if (!conf.quiet && !conf.debug)
		finish_display();
}


static void
exit_handler(void)
{
	finish_all();
}


static void
sigint_handler(__attribute__((unused)) int sig)
{
	exit(0);
}


static void
sigpipe_handler(__attribute__((unused)) int sig)
{
	/* ignore signal here - we will handle it after write failed */
}


void
init_spectrum(void)
{
	int i;

	for (i = 0; i < conf.num_channels && i < MAX_CHANNELS; i++) {
		list_head_init(&spectrum[i].nodes);
		ewma_init(&spectrum[i].signal_avg, 1024, 8);
		ewma_init(&spectrum[i].durations_avg, 1024, 8);
	}
}

static void
mac_name_file_read(const char* filename) {
	FILE* fp;
	char line[255];
	char macs[18];
	char name[18];
	int idx = 0;
	int n;

	if ((fp = fopen(filename, "r")) == NULL) {
		printlog("Could not open mac name file '%s'", filename);
		return;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		// first try dnsmasq dhcp.leases format
		n = sscanf(line, "%*s %17s %*s %17s", macs, name);
		if (n < 2) // if not MAC name
			n = sscanf(line, "%17s %17s", macs, name);
		if (n == 2) {
			convert_string_to_mac(macs, node_names.entry[idx].mac);
			strncpy(node_names.entry[idx].name, name, MAX_NODE_NAME_LEN);
			idx++;
		}
	}

	fclose(fp);

	node_names.count = idx;

	for (n = 0; n < node_names.count; n++) {
		printf("MAC %s = %s\n", ether_sprintf(node_names.entry[n].mac),
		       node_names.entry[n].name );
	}
}


const char* mac_name_lookup(const unsigned char* mac, int shorten_mac) {
	int i;
	if (conf.mac_name_lookup) {
		for (i = 0; i < node_names.count; i++) {
			if (memcmp(node_names.entry[i].mac, mac, MAC_LEN) == 0)
				return node_names.entry[i].name;
		}
	}
	return shorten_mac ? ether_sprintf_short(mac) : ether_sprintf(mac);
}


int
main(int argc, char** argv)
{
	list_head_init(&essids.list);
	list_head_init(&nodes);

	config_parse_file_and_cmdline(argc, argv);

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGHUP, sigint_handler);
	signal(SIGPIPE, sigpipe_handler);
	atexit(exit_handler);

	gettimeofday(&stats.stats_time, NULL);
	gettimeofday(&the_time, NULL);

	conf.channel_idx = -1;

	if (conf.mac_name_lookup)
		mac_name_file_read(conf.mac_name_file);

	if (conf.allow_control) {
		printlog("Allowing control socket '%s'", conf.control_pipe);
		control_init_pipe();
	}

	if (conf.serveraddr[0] != '\0')
		mon = net_open_client_socket(conf.serveraddr, conf.port);
	else {
		mon = open_packet_socket(conf.ifname, conf.recv_buffer_size);
		if (mon <= 0)
			err(1, "Couldn't open packet socket");

		conf.arphrd = device_get_hwinfo(mon, conf.ifname, conf.my_mac_addr);
		if (conf.arphrd != ARPHRD_IEEE80211_PRISM &&
		    conf.arphrd != ARPHRD_IEEE80211_RADIOTAP) {
			printf("You need to put your interface into monitor mode!\n");
			printf("(e.g. 'iw %s interface add mon0 type monitor' and 'horst -i mon0')\n", conf.ifname);
			exit(1);
		}

		channel_init();
		init_spectrum();
	}

	if (!conf.quiet && !conf.debug)
		init_display();

	if (!conf.serveraddr && conf.port && conf.allow_client)
		net_init_server_socket(conf.port);

	for ( /* ever */ ;;)
	{
		receive_any();
		gettimeofday(&the_time, NULL);
		timeout_nodes();

		if (conf.serveraddr[0] == '\0') { /* server */
			if (channel_auto_change()) {
				net_send_channel_config();
				update_spectrum_durations();
				if (!conf.quiet && !conf.debug)
					update_display(NULL);
			}
		}
	}
	/* will never */
	return 0;
}


void
main_pause(int pause)
{
	conf.paused = pause;
	printlog(conf.paused ? "- PAUSED -" : "- RESUME -");
}


void main_reset()
{
	if (!conf.quiet && !conf.debug)
		display_clear();
	printlog("- RESET -");
	free_lists();
	essids.split_active = 0;
	essids.split_essid = NULL;
	memset(&hist, 0, sizeof(hist));
	memset(&stats, 0, sizeof(stats));
	memset(&spectrum, 0, sizeof(spectrum));
	init_spectrum();
	gettimeofday(&stats.stats_time, NULL);
}


void
dumpfile_open(const char* name)
{
	if (DF != NULL) {
		fclose(DF);
		DF = NULL;
	}

	if (name == NULL || strlen(name) == 0) {
		printlog("- Not writing outfile");
		conf.dumpfile[0] = '\0';
		return;
	}

	strncpy(conf.dumpfile, name, MAX_CONF_VALUE_LEN);
	DF = fopen(conf.dumpfile, "w");
	if (DF == NULL)
		err(1, "Couldn't open dump file");

	printlog("- Writing to outfile %s", conf.dumpfile);
}


#if 0
void print_rate_duration_table(void)
{
	int i;

	printf("LEN\t1M l\t1M s\t2M l\t2M s\t5.5M l\t5.5M s\t11M l\t11M s\t");
	printf("6M\t9\t12M\t18M\t24M\t36M\t48M\t54M\n");
	for (i=10; i<=2304; i+=10) {
		printf("%d:\t%d\t%d\t", i,
			ieee80211_frame_duration(PHY_FLAG_G, i, 10, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 10, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 20, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 20, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 55, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 55, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 110, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 110, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));

		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 60, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 90, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 120, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 180, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 240, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 360, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 480, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\n",
			ieee80211_frame_duration(PHY_FLAG_G, i, 540, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
	}
}
#endif
