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
 * \defgroup moep80211_moep_hdr_ext Moep Header Extension
 * \brief The Moep Header Extension API is used to create, manipulate and delete
 * moep extension headers.
 *
 * \{
 * \file
 */
#ifndef __MOEP80211_MOEP_HDR_EXT_H
#define __MOEP80211_MOEP_HDR_EXT_H

#include <moep80211/types.h>
#include <moep80211/frame.h>


/* Possible values of header types */
#define MOEP_HDR_NEXTHDR_PRESENT	0x40

#define MOEP_HDR_MASK			(MOEP_HDR_NEXTHDR_PRESENT - 1)

enum moep_hdr_type {
	MOEP_HDR_INVALID		= 0x00,
	MOEP_HDR_PCTRL,

	MOEP_HDR_VENDOR_MIN		= 0x20,

	MOEP_HDR_COUNT			= MOEP_HDR_MASK + 1,
};

struct moep_hdr_ext {
	u8 type;
	u8 len;
} __attribute__((packed));

struct moep_hdr_pctrl {
	struct moep_hdr_ext hdr;
	u16 type;
	u16 len;
} __attribute__((packed));


/**
 * \brief moep header extension
 *
 * The function moep_frame_moep_hdr_ext() is used to get a moep header extension
 * of a frame.
 *
 * \param frame the frame
 * \param type the type of the header extension
 *
 * \return This function returns the moep header extension.
 *
 * \retval NULL on error (errno is set appropriately) or if the specified header
 * extension is not set.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not a moep frame.}
 * \errval{EINVAL, The parameter \paramname{type} is not a valid moep header
 * extension type.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
struct moep_hdr_ext *moep_frame_moep_hdr_ext(moep_frame_t frame,
					     enum moep_hdr_type type);

/**
 * \brief add a moep header extension
 *
 * The function moep_frame_add_moep_hdr_ext() is used to add a moep header
 * extension to a frame. Any previous header extension of the same type is
 * removed.
 *
 * \param frame the frame
 * \param type the type of the header extension
 * \param len the len of the header extension
 *
 * \return This function returns the new moep header extension.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not a moep frame.}
 * \errval{EINVAL, The parameter \paramname{type} is not a valid moep header
 * extension type.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
struct moep_hdr_ext *moep_frame_add_moep_hdr_ext(moep_frame_t frame,
						 enum moep_hdr_type type,
						 size_t len);

/**
 * \brief set a moep header extension
 *
 * The function moep_frame_set_moep_hdr_ext() is used to add a moep header
 * extension to a frame. Any previous header extension of the same type is
 * removed. The content of the header extension is copied to an internal buffer
 * so that \paramname{ext} does not need to be preserved.
 *
 * \param frame the frame
 * \param ext a pointer to the header extension
 *
 * \return This function returns the new moep header extension.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not a moep frame.}
 * \errval{EINVAL, Invalid argument}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
struct moep_hdr_ext *moep_frame_set_moep_hdr_ext(moep_frame_t frame,
						 struct moep_hdr_ext *ext);

/**
 * \brief delete a moep header extension
 *
 * The function moep_frame_del_moep_hdr_ext() is used to remove a moep header
 * extension from a frame.
 *
 * \param frame the frame
 * \param type the type of the header extension
 *
 * \retval 0 on success
 * \retval -1 on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{EACCES, The frame is not a moep frame.}
 * \errval{EINVAL, The parameter \paramname{type} is not a valid moep header
 * extension type.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
int moep_frame_del_moep_hdr_ext(moep_frame_t frame,
				enum moep_hdr_type type);

/** \} */
#endif /* __MOEP80211_MOEP_HDR_EXT_H */
