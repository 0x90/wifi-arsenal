/*
 * Reaver - Wireless interface functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "iface.h"

/* Populates globule->mac with the MAC address of the interface globule->iface */
int read_iface_mac()
{
	struct ifreq ifr;
	struct ether_addr *eth = NULL;
	int sock = 0, ret_val = 0;

	/* Need a socket for the ioctl call */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(sock != -1)
	{
		eth = malloc(sizeof(struct ether_addr));
		if(eth)
		{
			memset(eth, 0, sizeof(struct ether_addr));

			/* Prepare request */
			memset(&ifr, 0, sizeof(struct ifreq));
			strncpy(ifr.ifr_name, get_iface(), IFNAMSIZ);

			/* Do it */
			if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
			{
				set_mac((unsigned char *) &ifr.ifr_hwaddr.sa_data);
				ret_val = 1;
			}

			free(eth);
		}

		close(sock);
	}

	return ret_val;
}

/* 
 * Goes to the next 802.11 channel.
 * This is mostly required for APs that hop channels, which usually hop between channels 1, 6, and 11.
 * We just hop channels until we successfully associate with the AP.
 * The AP's actual channel number is parsed and set by parse_beacon_tags() in 80211.c.
 */
int next_channel()
{
        static int i;
	int n = 0;
        int bg_channels[] = BG_CHANNELS;
	int an_channels[] = AN_CHANNELS;
	int *channels = NULL;

	/* Select the appropriate channels for the target 802.11 band */
	if(get_wifi_band() == AN_BAND)
	{
		channels = (int *) &an_channels;
		n = sizeof(an_channels) / sizeof(int);
	}
	else
	{
		channels = (int *) &bg_channels;
		n = sizeof(bg_channels) / sizeof(int);
	}

	/* Only switch channels if fixed channel operation is disabled */
	if(!get_fixed_channel())
	{
        	i++;

        	if((i >= n) || i < 0)
        	{
        	        i = 0;
        	}

        	return change_channel(channels[i]);
	}
	
	return 0;
}

/* Sets the 802.11 channel for the selected interface */
int change_channel(int channel)
{
        int skfd = 0, ret_val = 0;
        struct iwreq wrq;

        memset((void *) &wrq, 0, sizeof(struct iwreq));

        /* Open NET socket */
        if((skfd = iw_sockets_open()) < 0)
        {
                perror("iw_sockets_open");
        }
        else if(get_iface())
        {
                /* Convert channel to a frequency */
                iw_float2freq((double) channel, &(wrq.u.freq));

                /* Fixed frequency */
                wrq.u.freq.flags = IW_FREQ_FIXED;

        	cprintf(VERBOSE, "[+] Switching %s to channel %d\n", get_iface(), channel);

                /* Set frequency */
                if(iw_set_ext(skfd, get_iface(), SIOCSIWFREQ, &wrq) >= 0)
                {
			set_channel(channel);
                        ret_val = 1;
                }

                iw_sockets_close(skfd);
        }

        return ret_val;
}
