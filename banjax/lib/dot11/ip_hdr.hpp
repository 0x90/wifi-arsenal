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

#ifndef DOT11_IP_HDR_HPP
#define DOT11_IP_HDR_HPP

#include <dot11/udp_hdr.hpp>
#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>
#include <stdint.h>

namespace dot11 {

   /**
    * ip_hdr is a concrete dissector class that provides access to the
    * IEEE IP header.
    */
   class ip_hdr {
   public:

      /**
       * Construct an ip_hdr from the specified buffer.
       *
       * \param A non-null pointer
       */
      explicit ip_hdr(net::buffer_sptr b);

      // compiler-generated:
      // ip(const ip& other);
      // ip& operator=(ip& other);
      // bool operator==(const ip& other);
      // ~ip();

      /**
       * Return the identifier for the encapsulated protocol.
       *
       * \return A uint8_t specifying the type of the encapsulated protocol.
       */
      uint8_t protocol() const;

      /**
       * Return the IPv4 source address.
       *
       * \return A uint32_t containing the source address.
       */
      uint32_t src_addr() const;

      /**
       * Return the IPv4 destination address.
       *
       * \return A uint32_t containing the destination address.
       */
      uint32_t dst_addr() const;

      /**
       * If present (protocol() == 0x11) returns a pointer to the UDP
       * header; otherwise returns a NULL pointer.
       *
       * \return A (possibly NULL) pointer to a udp_hdr.
       */
      udp_hdr_sptr get_udp_hdr() const;

      /**
       * Return the size of the IP header.
       *
       * \return A size_t specifying the size of the IP header.
       */
      static size_t min_size();

   private:

      /**
       * Pointer to the IP header and payload.
       */
      net::buffer_sptr buf_;

   };

   typedef boost::shared_ptr<ip_hdr> ip_hdr_sptr;

}

#endif // DOT11_IP_HDR_HPP
