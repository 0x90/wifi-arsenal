/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 Steve Glass
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

#ifndef DOT11_LLC_HDR_HPP
#define DOT11_LLC_HDR_HPP

#include <net/buffer.hpp>
#include <dot11/ip_hdr.hpp>

#include <boost/shared_ptr.hpp>
#include <stdint.h>

namespace dot11 {

   /**
    * llc is a concrete dissector class that provides access
    * to the IEEE LLC header.
    */
   class llc_hdr {
   public:

      /**
       * Construct an llc_hdr from the specified buffer.
       *
       * \param A non-null pointer to a buffer.
       */
      explicit llc_hdr(net::buffer_sptr b);

      // compiler-generated:
      // llc(const llc& other);
      // llc& operator=(llc& other);
      // bool operator==(const llc& other);
      // ~llc();

      // ToDo: accessors for other LLC header fields!

      /**
       * Return the type of the encapsulated payload.
       *
       * \return A uint16_t specifying the payload type.
       */
      uint16_t type() const;

      /**
       * Return a pointer to the IP header or NULL if this frame does
       * not contain an IP payload (i.e. type() == 0x0800).
       *
       * \return A (possibly NULL) pointer to an IP packet.
       */
      ip_hdr_sptr get_ip_hdr() const;

      /**
       * Return the size of the LLC header.
       *
       * \return A size_t specifying the size of the IP header.
       */
      static size_t min_size();

   private:

      /**
       * Pointer to the LLC header and payload.
       */
      net::buffer_sptr buf_;

   };

   typedef boost::shared_ptr<llc_hdr> llc_hdr_sptr;

}

#endif // DOT11_LLC_HDR_HPP
