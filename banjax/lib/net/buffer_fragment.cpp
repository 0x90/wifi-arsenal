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
 * 
 */

#include <net/buffer_fragment.hpp>
#include <util/dump.hpp>
#include <util/exceptions.hpp>

using namespace net;
using namespace std;
using util::dump;
using util::raise;

buffer_fragment::buffer_fragment(buffer_sptr buf) :
   buf_(buf),
   begin_(0),
   end_(buf->data_size())
{
}

buffer_fragment::buffer_fragment(buffer_sptr buf, size_t begin, size_t end) :
   buf_(buf),
   begin_(begin),
   end_(end)
{
   const size_t buf_sz = buf->data_size();
   if(!(begin < end && end <= buf_sz)) {
      ostringstream msg;
      msg << "cannot extract [" << begin << "," << end << ") from buffer of size " << buf_sz;
      msg << setbase(16) << setw(2) << setfill('0') << dump(buf_->data_size(), buf_->data()) << endl;
      raise<length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

buffer_fragment::~buffer_fragment()
{
}

const uint8_t*
buffer_fragment::data() const
{
   return(buf_->data() + begin_);
}

size_t
buffer_fragment::data_size() const
{
   return end_ - begin_;
}

buffer_info_sptr
buffer_fragment::info()
{
   return buf_->info();
}

const_buffer_info_sptr
buffer_fragment::info() const
{
   return buf_->info();
}

const uint8_t*
buffer_fragment::read_octets(size_t begin, size_t end) const
{
   return buf_->read_octets(begin_ + begin, begin_ + end);
}

void
buffer_fragment::write_octets(size_t begin, size_t end, const uint8_t *p)
{
   buf_->write_octets(begin_ + begin, begin_ + end, p);
}
