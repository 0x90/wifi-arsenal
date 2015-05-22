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

#include "config.h"

#ifdef SYS_LINUX

#include "madwifing_control.h"

#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>
#include <err.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#include "lorcon.h"
#include "ifcontrol_linux.h"

struct madwifi_vaps *madwifing_list_vaps(const char *ifname, char *errstr) {
	DIR *devdir;
	struct dirent *devfile;
	char dirpath[1024], owner[512];
	struct madwifi_vaps *vlist;
	int numv = 0;

	snprintf(dirpath, 1024, "/sys/class/net/%s/device/", ifname);

	if ((devdir = opendir(dirpath)) == NULL) {
		snprintf(errstr, LORCON_STATUS_MAX, "madwifing sys directory open failed: %s %s",
				 dirpath, strerror(errno));
		return NULL;
	}

	while ((devfile = readdir(devdir)) != NULL) {
		snprintf(owner, 512, "net:%s", ifname);

		if (strncmp("net:", devfile->d_name, 4) == 0 && 
			strcmp(devfile->d_name, owner))
			numv++;
	}

	rewinddir(devdir);

	vlist = (struct madwifi_vaps *) malloc(sizeof(struct madwifi_vaps));
	vlist->vaplist = (char **) malloc(sizeof(char *) * numv);
	vlist->vaplen = numv;

	numv = 0;

	while ((devfile = readdir(devdir)) != NULL) {
		snprintf(owner, 512, "net:%s", ifname);

		if (strncmp("net:", devfile->d_name, 4) == 0 && 
			strcmp(devfile->d_name, owner))
			vlist->vaplist[numv++] = strdup(devfile->d_name + 4);
	}

	return vlist;
}

void madwifing_free_vaps(struct madwifi_vaps *in_vaplist) {
	int n = 0;

	for (n = 0; n < in_vaplist->vaplen; n++) {
		free(in_vaplist->vaplist[n]);
	}
	free(in_vaplist->vaplist);
	free(in_vaplist);
}

int madwifing_destroy_vap(const char *ifname, char *errstr) {
	struct ifreq ifr;
	int sock;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to create socket to madwifi: %s",
				 strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOC80211IFDESTROY, &ifr) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Failed to destroy VAP: %s", strerror(errno));
		close(sock);
		return -1;
	}

	close(sock);

	return 1;
}

int madwifing_build_vap(const char *ifname, char *errstr, const char *vapname, 
						char *retvapname, int vapmode, int vapflags) {
	struct ieee80211_clone_params {
		char icp_name[IFNAMSIZ];
		uint16_t icp_opmode;
		uint16_t icp_flags;
	};
	struct ieee80211_clone_params cp;
	struct ifreq ifr;
	int sock;
	char tnam[IFNAMSIZ];
	int n;

	// Find a numbered vapname which is useable
	for (n = 0; n < 10; n++) {
		short fl;
		snprintf(tnam, IFNAMSIZ, "%s%d", vapname, n);
		if (ifconfig_get_flags(tnam, errstr, &fl) < 0)
			break;

		// Default to no temp name as error
		tnam[0] = '\0';
	}

	if (tnam[0] == '\0') {
		snprintf(errstr, 1024, "Unable to find free slot for VAP %s", vapname);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(&cp, 0, sizeof(cp));

	strncpy(cp.icp_name, tnam, IFNAMSIZ);
	cp.icp_opmode = vapmode;
	cp.icp_flags = vapflags;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = (caddr_t) &cp;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, 1024, "Unable to create socket to madwifi-ng: %s",
				 strerror(errno));
		return -1;
	}

	if (ioctl(sock, SIOC80211IFCREATE, &ifr) < 0) {
		snprintf(errstr, 1024, "Unable to create VAP: %s", strerror(errno));
		close(sock);
		return -1;
	}

	if (madwifing_setdevtype(ifr.ifr_name, ARPHDR_RADIOTAP, errstr) < 0) {
		return -1;
	}

	strncpy(retvapname, ifr.ifr_name, IFNAMSIZ);
	close(sock);

	return 1;
}

/* 
 * Set the device link type for the named interface by changing the dev_type
 * file in the sys filesystem.
 */
int madwifing_setdevtype(const char *ifname, char *devtype, char *errstr)
{
	FILE *fp;
	char athdevpath[64];
	int ret;

	snprintf(athdevpath, 64, "/proc/sys/net/%s/dev_type", ifname);
	
	fp = fopen(athdevpath, "w");
	if (!fp) {
		snprintf(errstr, LORCON_STATUS_MAX, "Error setting madwifi-ng "
				 "capture header type, unable to open proc device \"%s\"",
				 athdevpath);
		return -1;
	}

	ret = fprintf(fp, "%s\n", devtype);
	if (ret < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "Error setting madwifi-ng "
				 "capture header type, unable to write to proc device \"%s\"",
				 athdevpath);
		return ret;
	}

	fclose(fp);
	return 0;
}

char *madwifing_find_parent(struct madwifi_vaps *vaplist) {
	int x;

	for (x = 0; x < vaplist->vaplen; x++) {
		if (strncmp("wifi", vaplist->vaplist[x], 4) == 0)
			return strdup(vaplist->vaplist[x]);
	}

	return NULL;
}

#endif /* linux */

