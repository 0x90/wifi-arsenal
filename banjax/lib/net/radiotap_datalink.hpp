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

#ifndef NET_RADIOTAP_DATALINK_HPP
#define NET_RADIOTAP_DATALINK_HPP

#include <net/datalink.hpp>

#include <stdint.h>

namespace net {

   /**
    * A radiotap_datalink is one in which No frame header is present and
    * L2 frames are sent to the WNIC using an un-encpsulated
    * representation.
    */
   class radiotap_datalink : public datalink {
   public:

      /**
       * Default radiotap_datalink constructor.
       */
      radiotap_datalink();

      /**
       * (Virtual) destructor.
       */
      virtual ~radiotap_datalink();

      /**
       * Format the output frame so that it contains the appropriate
       * link-layer header. When calling format frame_sz specifies the
       * maximum size of the frame and this is modified to the actual
       * size of the frame when the function returns.
       *
       * \param b A reference to the buffer.       
       * \param frame_sz The maximum/actual size of the frame.
       * \param frame A non-null pointer to the output frame.
       */
      virtual size_t format(const buffer& b, size_t frame_sz, uint8_t *frame);

      /**
       * Return the name of this radiotap_datalink type.
       *
       * \return A pointer to the radiotap_datalink type name.
       */
      virtual const char *name() const;

      /**
       * Parse the specified layer 2 frame and return a buffer
       * containing the layer 2 frame minus the radiotap_datalink header.
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

   private:

      /**
       * Align the pointer p to the specified field_sz boundary and
       * return that value. A side-effect is that p is advanced over
       * the current entry.
       *
       * \param p The pointer value which, on return, is advanced to
       * the next entry. 
       * \return The value of p aligned to the next field_sz boundary.
       */
      uint8_t *advance(uint8_t *& p, uint8_t field_sz);

   private:

      /**
       * The physical format of the radiotap header.
       */
      struct radiotap_header {
         uint8_t version_;
         uint8_t pad_;
         uint16_t size_;
         uint32_t bitmaps_[1];
      } __attribute__((packed));

   };

}

#endif // NET_RADIOTAP_DATALINK_HPP
