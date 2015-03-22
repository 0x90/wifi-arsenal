/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2010-2011 Steve Glass
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

#ifndef NET_PLAIN_DATALINK_HPP
#define NET_PLAIN_DATALINK_HPP

#include <net/datalink.hpp>

namespace net {

   /**
    * A plain_datalink is one in which no datalink header is present.
    * L2 frames are passed between the kernel and WNIC using the same
    * representation as is used over the air.
    */
   class plain_datalink : public datalink {
   public:

      /**
       * Default plain_datalink constructor.
       */
      plain_datalink();

      /**
       * (Virtual) destructor.
       */
      virtual ~plain_datalink();

      /**
       * Format the output frame so that it contains the appropriate
       * link-layer header.
       *
       * \param b A reference to the buffer.       
       * \param frame_sz The maximum size of the frame.
       * \param frame A non-null pointer to the output frame.
       * \return The number of octets written to the buffer.
       */
      virtual size_t format(const buffer& b, size_t frame_sz, uint8_t *frame);

      /**
       * Return the name of this plain_datalink type.
       *
       * \return A pointer to the plain_datalink type name.
       */
      virtual const char *name() const;

      /**
       * Parse the specified layer 2 frame into a buffer.
       *
       * \param frame_sz The size of the frame to be parsed.
       * \param frame A non-null pointer to the frame.
       */
      virtual buffer_sptr parse(size_t frame_sz, const uint8_t *frame);

      // ToDo: filter offset logic.


      /**
       * Returns the ARP type for this datalink.
       *
       * \return An integer specifying the ARP type of this datalink.
       */
      virtual int type() const;
   };

}

#endif // NET_PLAIN_DATALINK_HPP
