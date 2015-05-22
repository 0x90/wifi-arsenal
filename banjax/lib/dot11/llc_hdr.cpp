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


llc_hdr::llc_hdr(buffer_sptr b) :
   buf_(b)
{
   CHECK_MIN_SIZE(b->data_size(), min_size());
}

uint16_t
llc_hdr::type() const
{
   return buf_->read_u16(6);
}

ip_hdr_sptr
llc_hdr::get_ip_hdr() const
{
   ip_hdr_sptr ip;
   if(type() == 0x0800) {
      buffer_sptr b(new buffer_fragment(buf_, min_size(), buf_->data_size()));
      ip = ip_hdr_sptr(new ip_hdr(b));
   }
   return ip;
}

size_t
llc_hdr::min_size()
{
   return 8;
}
