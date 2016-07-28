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
 * \defgroup moep80211_module Modules
 * \brief The Modules API is used to implement the modules. If you only want to
 * use the library, you do not need this. See below for the available
 * compiled-in modules.
 *
 * <b>Layer 2 modules:</b>
 * \li \ref moep80211_modules_ieee80211
 * \li \ref moep80211_modules_ieee8023
 * \li \ref moep80211_modules_moep80211
 * \li \ref moep80211_modules_moep8023
 *
 * <b>Layer 1 modules:</b>
 * \li \ref moep80211_modules_radio
 * \li \ref moep80211_modules_eth
 * \li \ref moep80211_modules_tap
 * \li \ref moep80211_modules_unix
 *
 * \{
 * \file
 */
#ifndef __MOEP80211_MODULE_H
#define __MOEP80211_MODULE_H

#include <stddef.h>

#include <moep80211/types.h>
#include <moep80211/frame.h>
#include <moep80211/dev.h>


/**
 * \brief frame header operations
 *
 * The struct moep_frame_ops defines the operations needed to handle the frame
 * headers for the protocol defined by a module.
 */
struct moep_frame_ops {

	/**
	 * \brief create a header
	 *
	 * The function create() should allocate a new header and initialize
	 * some default values.
	 *
	 * \return This function should return the new header.
	 *
	 * \retval NULL on error, errno should be set appropriately.
	 */
	void *(* create)(void);

	/**
	 * \brief parse a header
	 *
	 * The function parse() should parse the buffer \paramname{raw} and
	 * create a new header with the parsed data. The pointer \paramname{raw}
	 * should afterwards point behind the parsed data and \paramname{maxlen}
	 * should be decremented by the length of the parsed data.
	 *
	 * \param raw a pointer to the buffer
	 * \param maxlen the available length in the buffer
	 *
	 * \return This function should return the new header.
	 *
	 * \retval NULL on error, errno should be set appropriately.
	 */
	void *(* parse)(u8 **raw, size_t *maxlen);

	/**
	 * \brief length of the built header
	 *
	 * The function build_len() should compute the size the header will need
	 * to be built.
	 *
	 * \param hdr the header
	 *
	 * \return This function should return the length of the built header.
	 *
	 * \retval -1 on error, errno should be set appropriately.
	 */
	int (* build_len)(void *hdr);

	/**
	 * \brief build a header
	 *
	 * The function build() should build the header into the buffer
	 * \paramname{raw}.
	 *
	 * \param hdr the header
	 * \param raw the buffer
	 * \param maxlen the available length in the buffer
	 *
	 * \return This function should return the length of the built header.
	 *
	 * \retval -1 on error, errno should be set appropriately.
	 */
	int (* build)(void *hdr, u8 *raw, size_t maxlen);

	/**
	 * \brief destroy a header
	 *
	 * The function destroy() should destroy the header and release all
	 * associated ressources.
	 *
	 * \param hdr the header
	 */
	void (* destroy)(void *hdr);
};


/**
 * \brief create a frame
 *
 * The function moep_frame_create() is used to create a frame with the given
 * frame header operations.
 *
 * \param l1_ops frame header operations for layer 1
 * \param l2_ops frame header operations for layer 2
 *
 * \return This function returns a moep frame.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{ }
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
moep_frame_t moep_frame_create(struct moep_frame_ops *l1_ops,
			       struct moep_frame_ops *l2_ops);

/**
 * \brief convert a frame
 *
 * The function moep_frame_convert() is used to convert the headers of a frame
 * to the format required by the given frame header operations. This function
 * does not convert any header data, it only removes the old headers and creates
 * new empty headers in the specified format. This function is useful if you
 * want to convert a frame, without copying the payload.
 *
 * \param frame the frame
 * \param l1_ops frame header operations for layer 1
 * \param l2_ops frame header operations for layer 2
 */
void moep_frame_convert(moep_frame_t frame, struct moep_frame_ops *l1_ops,
			struct moep_frame_ops *l2_ops);

/**
 * \brief layer 1 header
 *
 * The function moep_frame_l1_hdr() is used to get the layer 1 header of a
 * frame.
 *
 * \param frame the frame
 * \param l1_ops frame header operations for layer 1
 *
 * \return This function returns the layer 1 header.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{These are some standard errors generated by this function. Additional
 * errors may be generated and returned from the underlying device specific
 * functions.}
 * \errval{EACCES, The frame has not the header format specified by
 * \paramname{l1_ops}.}
 * \enderrors
 */
void *moep_frame_l1_hdr(moep_frame_t frame, struct moep_frame_ops *l1_ops);

/**
 * \brief layer 2 header
 *
 * The function moep_frame_l2_hdr() is used to get the layer 2 header of a
 * frame.
 *
 * \param frame the frame
 * \param l2_ops frame header operations for layer 2
 *
 * \return This function returns the layer 2 header.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{These are some standard errors generated by this function. Additional
 * errors may be generated and returned from the underlying device specific
 * functions.}
 * \errval{EACCES, The frame has not the header format specified by
 * \paramname{l2_ops}.}
 * \enderrors
 */
void *moep_frame_l2_hdr(moep_frame_t frame, struct moep_frame_ops *l2_ops);


/**
 * \brief moep device operations
 *
 * The struct moep_dev_ops defines the operations needed to handle the device
 * defined by a module.
 */
struct moep_dev_ops {

	/**
	 * \brief close a device
	 *
	 * The function close() should close the device and release all
	 * associated ressources.
	 *
	 * \param fd the file descriptor passed to moep_dev_open()
	 * \param priv the private data passed to moep_dev_open()
	 *
	 * \retval 0 on success
	 * \retval -1 on error, errno should be set appropriately.
	 */
	int (* close)(int fd, void *priv);
};


/**
 * \brief open a moep device
 *
 * The function moep_dev_open() is used to open a moep device. The passed file
 * descriptor must refer to the underlying device and support read and write
 * operations. The MTU includes all headers.
 *
 * \param fd file descriptor of the device
 * \param mtu the MTU of the device
 * \param ops moep device operations
 * \param priv private data
 * \param l1_ops frame header operations for layer 1
 * \param l2_ops frame header operations for layer 2
 *
 * \return This function returns a new moep device.
 *
 * \retval NULL on error, errno is set appropriately.
 *
 * \errors{These are some standard errors generated and returned by this
 * function. Additional errors may be generated and returned from the underlying
 * system calls.}
 * \errval{EINVAL, Invalid argument}
 * \errval{EMFILE, Too many open files; Some file descriptors are too big for
 * select.}
 * \errval{ENOMEM, Not enough memory available}
 * \enderrors
 */
moep_dev_t moep_dev_open(int fd, int mtu, struct moep_dev_ops *ops, void *priv,
			 struct moep_frame_ops *l1_ops,
			 struct moep_frame_ops *l2_ops);

/**
 * \brief return the private data of a moep device
 *
 * The function moep_dev_get_priv() is used to get the private data of the moep
 * device.
 *
 * \param dev the moep device
 * \param ops moep device operations
 *
 * \return This function returns the private data of the moep device.
 *
 * \retval NULL on error (errno is set appropriately) or if the private data is
 * NULL
 *
 * \errors{ }
 * \errval{EACCES, The moep device has not the type specified by
 * \paramname{ops}}
 * \enderrors
 */
void *moep_dev_get_priv(moep_dev_t dev, struct moep_dev_ops *ops);

/** \} */
#endif /* __MOEP80211_MODULE_H */
