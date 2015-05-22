/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2010 Steve Glass
 * 
 * This file is part of banjax.
 * 
 * Banjax is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * Banjax is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 */

#ifndef NET_PRISM2_DATALINK_HPP
#define NET_PRISM2_DATALINK_HPP

#include <net/datalink.hpp>

namespace net {

   /**
    * A prism2_datalink is one in which No frame header is present and
    * L2 frames are sent to the WNIC using an un-encpsulated
    * representation.
    */
   class prism2_datalink : public datalink {
   public:

      /**
       * Default prism2_datalink constructor.
       */
      prism2_datalink();

      /**
       * (Virtual) destructor.
       */
      virtual ~prism2_datalink();

      /**
       * Return the name of this prism2_datalink type.
       *
       * \return A pointer to the prism2_datalink type name.
       */
      virtual const char *name() const;

      /**
       * Parse the layer 2 frame and return a heap-allocated buffer.
       *
       * \param frame_sz The size of the frame to be parsed.
       * \param frame A non-null pointer to the frame.
       * \return A buffer_sptr pointing to the buffer.
       */
      virtual buffer_sptr parse(size_t frame_sz, const uint8_t *frame);

      /**
       * Format the output frame so that it contains the appropriate
       * link-layer header. When calling format frame_sz specifies the
       * maximum size of the frame and this is modified to the actual
       * size of the frame when the function returns.
       *
       * \param buf A non-null pointer to the buffer.       
       * \param frame_sz The maximum size of the frame.
       * \param frame A non-null pointer to the output frame.
       * \return The number of octets written to the buffer.
       */
      virtual size_t format(buffer *buf, size_t frame_sz, uint8_t *frame);

      // ToDo: filter offset logic.

   };

}

#endif // NET_PRISM2_DATALINK_HPP
