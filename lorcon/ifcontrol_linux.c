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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ifcontrol_linux.h"
#include "lorcon.h"

char *ifconfig_get_sysdriver(const char *in_dev) 
{
	char devlinktarget[512];
	ssize_t devlinklen;
	char devlink[256];
	char *rind = NULL;

	snprintf(devlink, 256, "/sys/class/net/%s/device/driver", in_dev);

	devlinklen = readlink(devlink, devlinktarget, 511);
	if (devlinklen > 0) {
		devlinktarget[devlinklen] = '\0';
		rind = rindex(devlinktarget, '/');
		// If we found it and not at the end of the line
		if (rind != NULL && (rind - devlinktarget) + 1 < devlinklen)
			return strdup(rind + 1);
	}

	return NULL;
}

int ifconfig_get_sysattr(const char *in_dev, const char *attr) 
{
	char devlink[256];
	struct stat buf;

	snprintf(devlink, 256, "/sys/class/net/%s/%s", in_dev, attr);

	if (stat(devlink, &buf) != 0)
		return 0;

	return 1;
}

int ifconfig_set_flags(const char *in_dev, char *errstr, short flags)
{
	struct ifreq ifr;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "SetIFFlags: Failed to create AF_INET "
			 "DGRAM socket. %d:%s", errno, strerror(errno));
		return -1;
	}

	/* Fetch interface flags */
	strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
	ifr.ifr_flags = flags;
	if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX, "%s %s",
				 __FUNCTION__, strerror(errno));
		close(skfd);
		return -1;
	}

	close(skfd);

	return 0;
}

int ifconfig_get_flags(const char *in_dev, char *errstr, short *flags)
{
	struct ifreq ifr;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "GetIFFlags: Failed to create AF_INET "
			 "DGRAM socket. %d:%s", errno, strerror(errno));
		return -1;
	}

	/* Fetch interface flags */
	strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "GetIFFlags: interface %s: %s", in_dev,
			 strerror(errno));
		close(skfd);
		return -1;
	}

	(*flags) = ifr.ifr_flags;

	close(skfd);

	return 0;
}

int ifconfig_delta_flags(const char *in_dev, char *errstr, short flags)
{
	int ret;
	short rflags;

	if ((ret = ifconfig_get_flags(in_dev, errstr, &rflags)) < 0)
		return ret;

	rflags |= flags;

	return ifconfig_set_flags(in_dev, errstr, rflags);
}

int ifconfig_get_hwaddr(const char *in_dev, char *errstr, uint8_t * ret_hwaddr)
{
	struct ifreq ifr;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "Getting HWAddr: failed to create AF_INET "
			 "DGRAM socket. %d:%s", errno, strerror(errno));
		return -1;
	}

	/* Fetch interface flags */
	strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "%s %s", in_dev, __FUNCTION__, strerror(errno));
		close(skfd);
		return -1;
	}

	memcpy(ret_hwaddr, ifr.ifr_hwaddr.sa_data, 6);

	close(skfd);

	return 0;
}

int ifconfig_set_hwaddr(const char *in_dev, char *errstr, uint8_t * in_hwaddr)
{
	struct ifreq ifr;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "Setting HWAddr: failed to create AF_INET "
			 "DGRAM socket. %d:%s", errno, strerror(errno));
		return -1;
	}

	strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);

	/* Instead of specifying the sa_family for ifr_hwaddr as ARPHDR_ETHER,
	 * we retrieve it from SIOCGIFHWADDR for maximum compatibility.
	 */
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "Getting HWAddr: interface %s: %s", in_dev,
			 strerror(errno));
		close(skfd);
		return -1;
	}

	memcpy(ifr.ifr_hwaddr.sa_data, in_hwaddr, 6);

	if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "Setting HWAddr: interface %s: %s", in_dev,
			 strerror(errno));
		close(skfd);
		return -1;
	}

	close(skfd);

	return 0;
}

int ifconfig_set_mtu(const char *in_dev, char *errstr, uint16_t in_mtu)
{
	struct ifreq ifr;
	int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "Setting MTU: failed to create AF_INET "
			 "DGRAM socket. %d:%s", errno, strerror(errno));
		return -1;
	}

	/* Fetch interface flags */
	strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
	ifr.ifr_mtu = in_mtu;
	if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
		snprintf(errstr, LORCON_STATUS_MAX,
			 "%s %s", in_dev, __FUNCTION__, strerror(errno));
		close(skfd);
		return -1;
	}

	close(skfd);

	return 0;
}

int ifconfig_ifupdown(const char *in_dev, char *errstr, int devup)
{
	int ret;
	short rflags;

	if ((ret = ifconfig_get_flags(in_dev, errstr, &rflags)) < 0)
		return ret;

	if (devup) {
		rflags |= IFF_UP;
	} else {
		rflags &= ~IFF_UP;
	}

	return ifconfig_set_flags(in_dev, errstr, rflags);
}

#endif
