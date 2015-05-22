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

#include <net/buffer_body.hpp>
#include <net/prism2_datalink.hpp>

#include <algorithm>

using namespace net;

prism2_datalink::prism2_datalink()
{
}

prism2_datalink::~prism2_datalink()
{
}

const char*
prism2_datalink::name() const
{
   return "prism2";
}

buffer_sptr
prism2_datalink::parse(size_t frame_sz, const uint8_t *frame)
{
   // ToDo: implement me!
   return buffer_sptr(new buffer_body(frame_sz, frame));
}

size_t
prism2_datalink::format(buffer *buf, size_t frame_sz, uint8_t *frame)
{
   size_t n = std::min(frame_sz, buf->data_size());
   // ToDo: implement me!
   return n;
}
