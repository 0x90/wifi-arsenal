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

#include <dot11/llc_hdr.hpp>
#include <net/buffer_fragment.hpp>
#include <util/exceptions.hpp>

using namespace dot11;
using namespace net;
using namespace std;


ip_hdr::ip_hdr(buffer_sptr b) :
   buf_(b)
{
   CHECK_MIN_SIZE(b->data_size(), min_size());
}

uint8_t
ip_hdr::protocol() const
{
   return buf_->read_u8(9);
}

udp_hdr_sptr
ip_hdr::get_udp_hdr() const
{
   udp_hdr_sptr udp;
   if(protocol() == 0x11) {
      buffer_sptr b(new buffer_fragment(buf_, min_size(), buf_->data_size()));
      udp = udp_hdr_sptr(new udp_hdr(b));
   }
   return udp;
}

size_t
ip_hdr::min_size()
{
   return 20;
}
