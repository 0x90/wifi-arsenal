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
 * \defgroup moep80211_modules_radio Radio
 * \ingroup moep80211_module
 * \{
 * \file
 */
#ifndef __MOEP80211_MODULES_RADIO_H
#define __MOEP80211_MODULES_RADIO_H

#include <moep80211/dev.h>
#include <moep80211/frame.h>
#include <moep80211/radiotap.h>


/**
 * \brief channel width definition
 */
enum moep80211_chan_width {

	/**
	 * \brief 20 MHz, non-HT channel
	 */
	MOEP80211_CHAN_WIDTH_20_NOHT,

	/**
	 * \brief 20 MHz, HT channel
	 */
	MOEP80211_CHAN_WIDTH_20,

	/**
	 * \brief 40 MHz channel
	 *
	 * This channel type requires the parameter \paramname{freq1} to be
	 * specified.
	 */
	MOEP80211_CHAN_WIDTH_40,

	/**
	 * \brief 80 MHz channel
	 *
	 * This channel type requires the parameter \paramname{freq1} to be
	 * specified.
	 */
	MOEP80211_CHAN_WIDTH_80,

	/**
	 * \brief 80+80 MHz channel
	 *
	 * This channel type requires the parameters \paramname{freq1} and
	 * \paramname{freq2} to be specified.
	 */
	MOEP80211_CHAN_WIDTH_80P80,

	/**
	 * \brief 160 MHz channel
	 *
	 * This channel type requires the parameter \paramname{freq1} to be
	 * specified.
	 */
	MOEP80211_CHAN_WIDTH_160,
};

struct moep_frame_ops;


/**
 * \brief open a radio device
 *
 * The function moep_dev_radio_open() is used to open a radio device. This
 * function is only useful, if you want to create a new layer 2 module based on
 * the radio module.
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
 * \param l2_ops frame header operations for layer 2
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
moep_dev_t moep_dev_radio_open(const char *devname, u32 freq,
			       enum moep80211_chan_width chan_width,
			       u32 freq1, u32 freq2, int mtu,
			       struct moep_frame_ops *l2_ops);

/**
 * \brief create a radio frame
 *
 * The function moep_frame_radio_create() is used to create a radio frame with
 * the given frame header operations for layer 2.
 *
 * \param l2_ops frame header operations for layer 2
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{The error values are the same as for moep_frame_create().}
 * \enderrors
 */
moep_frame_t moep_frame_radio_create(struct moep_frame_ops *l2_ops);

/**
 * \brief radiotap header
 *
 * The function moep_frame_radiotap() is used to get the radiotap header of a
 * frame.
 *
 * \param frame the frame
 *
 * \return This function returns the radiotap header.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not a radio frame.}
 * \errval{ENOMEM, Not enough memory available.}
 * \enderrors
 */
struct moep80211_radiotap *moep_frame_radiotap(moep_frame_t frame);

/** \} */
#endif /* __MOEP80211_MODULES_RADIO_H */
