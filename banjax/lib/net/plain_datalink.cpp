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
 * x
 */

#include <net/buffer_body.hpp>
#include <net/plain_datalink.hpp>
#include <util/exceptions.hpp>

#include <algorithm>
#include <pcap.h>

using namespace net;
using namespace std;

plain_datalink::plain_datalink()
{
}

plain_datalink::~plain_datalink()
{
}

size_t
plain_datalink::format(const buffer& b, size_t frame_sz, uint8_t *frame)
{
   CHECK_NOT_NULL(frame);
   size_t n = std::min(frame_sz, b.data_size());
   const uint8_t *buf = b.data();
   copy(&buf[0], &buf[n], frame);
   return n;
}

const char*
plain_datalink::name() const
{
   return "IEEE 802.11";
}

buffer_sptr
plain_datalink::parse(size_t frame_sz, const uint8_t *frame)
{
   CHECK_NOT_NULL(frame);
   return buffer_sptr(new buffer_body(frame_sz, frame));
}

int
plain_datalink::type() const
{
   return DLT_IEEE802_11;
}
