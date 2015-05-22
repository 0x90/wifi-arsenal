/*
    bully - retrieve WPA/WPA2 passphrase from a WPS-enabled AP

    Copyright (C) 2012  Brian Purcell <purcell.briand@gmail.com>

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
#include "iface.h"


int set_chan(struct global *G, int chan)
{
	if (!G->index[chan]) {
		vprint("[X] AP channel '%d' not found in the current channel list\n", chan);
		exit(5);
	};
	return set_chanx(G, G->index[chan]);
};


int set_chanx(struct global *G, int chanx)
{
        int sock = 0, freq, result, channel = 0;
        struct iwreq wrq;
	memset(&wrq, 0, sizeof(struct iwreq));
	strncpy(wrq.ifr_name, G->ifname, IFNAMSIZ);
        if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                vprint("[!] Socket open for ioctl() on '%s' failed with '%d'\n", G->ifname, sock);
		return 0;
	};
	if (chanx) {
		channel = G->chans[chanx];
		wrq.u.freq.m = (double)channel;
		wrq.u.freq.e = (double)0;
		wrq.u.freq.flags = IW_FREQ_FIXED;
                vprint("[+] Switching interface '%s' to channel '%d'\n", G->ifname, channel);
		if (ioctl(sock, SIOCSIWFREQ, &wrq) < 0) {
			usleep(10000);
			if ((result = ioctl(sock, SIOCSIWFREQ, &wrq)) < 0) {
				vprint("[!] ioctl(SIOCSIWFREQ) on '%s' failed with '%d'\n", G->ifname, result);
				vprint("[X] Unable to set channel on '%s', exiting\n", G->ifname);
				exit(8);
			};
		};
	} else {
		if (ioctl(sock, SIOCGIWFREQ, &wrq) < 0) {
			vprint("[!] ioctl(SIOCGIWFREQ) on '%s' failed with '%d'\n", G->ifname, result);
		} else {
			freq = wrq.u.freq.m;
			if (freq < 100000000) freq *= 100000000;
			for (chanx=1; chanx<=G->chans[0]; chanx++)
				if (freq == G->freqs[chanx]) {
					channel = G->chans[chanx];
					goto set_exit;
				};
			vprint("[X] Unknown frequency '%d' reported by interface '%s'\n", freq, G->ifname);
		};
		chanx = channel = 0;
	};
set_exit:
	close(sock);
	if (channel)
		snprintf(G->schan, 8, "%d", channel);
	else
		memcpy(G->schan, "unknown", 8);
        return chanx;
};


int next_chan(struct global *G)
{
	int next = G->chanx + 1;
	if (G->chans[0] < next)
		next = 1;
	return set_chanx(G, next);
};


int get_hwmac(char *ifname, uint8 *mac)
{
        int sock = 0, result;
        struct ifreq irq;
	memset(&irq, 0, sizeof(struct iwreq));
	strncpy(irq.ifr_name, ifname, IFNAMSIZ);
        if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return sock;
	if ((result = ioctl(sock, SIOCGIFHWADDR, &irq)) < 0)
		return result;
	memcpy(mac, irq.ifr_hwaddr.sa_data, 6);
	close(sock);
        return 0;
};

