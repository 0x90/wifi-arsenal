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

#include <dot11/udp_hdr.hpp>
#include <net/buffer_fragment.hpp>
#include <util/exceptions.hpp>

using namespace dot11;
using namespace std;
using namespace net;


udp_hdr::udp_hdr(buffer_sptr b) :
   buf_(b)
{
   CHECK_MIN_SIZE(b->data_size(), min_size());
}

uint16_t
udp_hdr::src_port() const
{
   return buf_->read_u16(0);
}

uint16_t
udp_hdr::dst_port() const
{
   return buf_->read_u16(2);
}

buffer_sptr
udp_hdr::get_payload() const
{
   return buffer_sptr(new buffer_fragment(buf_, min_size(), buf_->data_size()));
}

size_t
udp_hdr::min_size()
{
   return 8;
}
