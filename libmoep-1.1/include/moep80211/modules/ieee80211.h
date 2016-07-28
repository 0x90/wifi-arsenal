/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 * 				Stephan M. Guenther <moepi@moepi.net>
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

/**
 * \defgroup moep80211_modules_ieee80211 ieee80211
 * \ingroup moep80211_module
 * \{
 * \file
 */
#ifndef __MOEP80211_MODULES_IEEE80211_H
#define __MOEP80211_MODULES_IEEE80211_H

#include <moep80211/dev.h>
#include <moep80211/frame.h>
#include <moep80211/ieee80211_frametypes.h>

#include <moep80211/modules/radio.h>


struct ieee80211_hdr_gen {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[IEEE80211_ALEN];
	u8 addr2[IEEE80211_ALEN];
	u8 addr3[IEEE80211_ALEN];
	__le16 seq_ctrl;
	u8 addr4[IEEE80211_ALEN];
	__le16 qos_ctrl;
	__le32 ht_ctrl;
} __attribute__((packed));


/**
 * \brief open an ieee80211 device
 *
 * The function moep_dev_ieee80211_open() is used to open an ieee80211 device.
 *
 * \param devname the device name; This can either be the physical device name
 * e.g. 'phy0' or an interface name e.g. 'wlan1'.
 * \param freq the channel frequency in MHz
 * \param chan_width the channel width
 * \param freq1 the first center frequency in MHz; This value may be ignored
 * depending on the channel width.
 * \param freq2 the second center frequency in MHz; This value may be ignored
 * depending on the channel width.
 * \param mtu the MTU of the device; This includes all headers.
 *
 * \return This function returns a moep device.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{These are some standard errors generated and returned by this
 * function. Additional errors may be generated and returned from the underlying
 * system calls.}
 * \errval{EINVAL, Invalid argument}
 * \errval{EMFILE, Too many open files; Some filedescriptors are too big for
 * select.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
moep_dev_t moep_dev_ieee80211_open(const char *devname, u32 freq,
				   enum moep80211_chan_width chan_width,
				   u32 freq1, u32 freq2, int mtu);

/**
 * \brief create a ieee80211 frame
 *
 * The function moep_frame_ieee80211_create() is used to create a ieee80211
 * frame.
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_ieee80211_create(void);

/**
 * \brief ieee80211 header
 *
 * The function moep_frame_ieee80211_hdr() is used to get the ieee80211 header
 * of a frame.
 *
 * \param frame the frame
 *
 * \return This function returns the ieee80211 header.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not an ieee80211 frame.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
struct ieee80211_hdr_gen *moep_frame_ieee80211_hdr(moep_frame_t frame);

/** \} */
#endif /* __MOEP80211_MODULES_IEEE80211_H */
