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
 * \defgroup moep80211_modules_moep80211 moep80211
 * \ingroup moep80211_module
 * \{
 * \file
 */
#ifndef __MOEP80211_MODULES_MOEP80211_H
#define __MOEP80211_MODULES_MOEP80211_H

#include <stddef.h>

#include <moep80211/dev.h>
#include <moep80211/frame.h>
#include <moep80211/moep_hdr_ext.h>
#include <moep80211/ieee80211_frametypes.h>

#include <moep80211/modules/radio.h>
#include <moep80211/modules/unix.h>


/*
 * Since the frame discritiminator consists of the higher 32bit of third address
 * field, we have to choose this value s.t. it does not reflect a valid MAC
 * address. At this thime the best we can do is to chose an OUI and set the
 * locally administered bit to zero (otherwise there is no OUI and it would be
 * possible that we encounter this address by accident).  Since the IANA does
 * not produce many NICs to our knowledge, we use their OUI and make sure by
 * means of the 4th octet, that the address is currently unassigned.
 * See http://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xml
 */
#define MOEP80211_FRAME_DISCRIMINATOR		0xff5e0000


/*
 * Generic moep80211 header:
 * The structure strictly follows the IEEE802.11 3-address data frame format,
 * except for the third address field that is redefined. The higher 32bit are
 * used to differentiate between IEEE80211 and moep80211 frames. This is done by
 * setting the discriminator field to MOEP80211_FRAME_DISCRIMINATOR. The lower
 * 16bit are used as transmitter-specific sequence number, which is used for
 * channel estimation.
 */
struct moep80211_hdr {
	u16 frame_control;
	u16 duration_id;
	u8 ra[IEEE80211_ALEN];
	u8 ta[IEEE80211_ALEN];
	u32 disc;
	u16 txseq;
	u16 seq_ctrl;
} __attribute__((packed));


/**
 * \brief open a moep80211 device
 *
 * The function moep_dev_moep80211_open() is used to open a moep80211 device.
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
moep_dev_t moep_dev_moep80211_open(const char *devname, u32 freq,
				   enum moep80211_chan_width chan_width,
				   u32 freq1, u32 freq2, int mtu);

/**
 * \brief open a moep80211 unix device
 *
 * The function moep_dev_moep80211_unix_open() is used to open a moep80211 unix
 * device.
 *
 * \param devname the device name; This must be the path of a unix domain
 * socket.
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
moep_dev_t moep_dev_moep80211_unix_open(const char *devname, int mtu);

/**
 * \brief create a moep80211 frame
 *
 * The function moep_frame_moep80211_create() is used to create a moep80211
 * frame.
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_moep80211_create(void);

/**
 * \brief create a moep80211 unix frame
 *
 * The function moep_frame_moep80211_unix_create() is used to create a moep80211
 * unix frame.
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_moep80211_unix_create(void);

/**
 * \brief moep80211 header
 *
 * The function moep_frame_moep80211_hdr() is used to get the moep80211 header
 * of a frame.
 *
 * \param frame the frame
 *
 * \return This function returns the moep80211 header.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not a moep80211 frame.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
struct moep80211_hdr *moep_frame_moep80211_hdr(moep_frame_t frame);

/** \} */
#endif /* __MOEP80211_MODULES_MOEP80211_H */
