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

#ifndef NET_DATALINK_HPP
#define NET_DATALINK_HPP

#include <net/buffer.hpp>

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>

namespace net {

   /**
    * Alias for boost::shared_ptr<datalink>.
    */
   typedef boost::shared_ptr<class datalink> datalink_sptr;

   /**
    * datalink is a class that understands the link-layer
    * encapsulation mechanism. The datalink can parse the
    * encapsulation header of received frames, format frames with an
    * appropriate header and create BPF filters that account for the
    * frame header.
    */
   class datalink : public boost::noncopyable {
   public:

      /**
       * Get a datalink instance appropriate to the datalink_type.
       *
       * \param datalink_type The ARP type for the datalink.
       * \return A non-null datalink_sptr pointing to a datalink instance.
       * \throws 
       */
      static datalink_sptr get(int datalink_type);

      /**
       * (Virtual) destructor.
       */
      virtual ~datalink();

      /**
       * Write buffer buf into frame with an appropriate
       * datalink-specific header.
       *
       * \param buf A reference to the buffer.
       * \param frame_sz The maximum size of the frame.
       * \param frame A non-null pointer to the output frame.
       * \return The actual number of octets written into frame.
       */
      virtual size_t format(const buffer& b, size_t frame_sz, uint8_t *frame) = 0;

      /**
       * Return the name of this datalink type.
       *
       * \return A pointer to a string naming this datalink type.
       */
      virtual const char *name() const = 0;

      /**
       * Parse the layer 2 frame and return a heap-allocated buffer.
       *
       * \param frame_sz The size of the frame to be parsed.
       * \param frame A non-null pointer to the frame.
       * \return A buffer_sptr pointing to the buffer.
       */
      virtual buffer_sptr parse(size_t frame_sz, const uint8_t *frame) = 0;

      // ToDo: filter offset logic.

      /**
       * Returns the ARP type for this datalink.
       *
       * \return An integer specifying the ARP type of this datalink.
       */
      virtual int type() const = 0;

   protected:

      /**
       * Default datalink constructor.
       */
      datalink();

   };

}

#endif // NET_DATALINK_HPP
