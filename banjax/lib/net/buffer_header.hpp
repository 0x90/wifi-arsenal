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

#ifndef NET_BUFFER_HEADER_HPP
#define NET_BUFFER_HEADER_HPP

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>

#include <stddef.h>
#include <stdint.h>

namespace net {

   /**
    * buffer_header provides additional info about a buffer and the
    * rx_info, tx_hint and tx_info sub-types provides access to this
    * information. Note that the buffer_header itself is not
    * transmitted over the air but used only for communication between
    * the userland and the network stack/device driver.
    */

   class buffer_header : public boost::noncopyable {
   public:
      virtual ~buffer_header();
      virtual size_t prepare(size_t octets_sz, uint8_t *octets) const = 0;
   protected:
      buffer_header();
   };

   typedef boost::shared_ptr<net::buffer_header> buffer_header_sptr;
   typedef boost::shared_ptr<const net::buffer_header> const_buffer_header_sptr;

}

#endif // NET_BUFFER_HEADER_HPP
