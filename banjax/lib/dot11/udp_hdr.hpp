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

#ifndef DOT11_UDP_HDR_HPP
#define DOT11_UDP_HDR_HPP

#include <net/buffer.hpp>

#include <boost/shared_ptr.hpp>
#include <stdint.h>

namespace dot11 {

   /**
    * udp_hdr is a concrete dissector class that provides access to the
    * IEEE UDP header.
    */
   class udp_hdr {
   public:

      /**
       * Construct an udp_hdr from the specified buffer.
       *
       * \param A non-null pointer
       */
      explicit udp_hdr(net::buffer_sptr b);

      // compiler-generated:
      // udp(const udp& other);
      // udp& operator=(udp& other);
      // bool operator==(const udp& other);
      // ~udp();

      /**
       * Return the UDP source port.
       *
       * \return A uint16_t specifying the source port.
       */
      uint16_t src_port() const;

      /**
       * Return the UDP destination port.
       *
       * \return A uint16_t specifying the destination port.
       */
      uint16_t dst_port() const;

      /**
       * Return a pointer to a buffer containing the packet payload.
       *
       * A non-null pointer to a (possibly zero-sized) buffer.
       */
      net::buffer_sptr get_payload() const;

      /**
       * Return the minimum size of the UDP header.
       *
       * \return A size_t specifying the size of the UDP header.
       */
      static size_t min_size();

   private:

      /**
       * Pointer to the UDP header and payload.
       */
      net::buffer_sptr buf_;

   };

   typedef boost::shared_ptr<udp_hdr> udp_hdr_sptr;

}

#endif // DOT11_UDP_HDR_HPP
