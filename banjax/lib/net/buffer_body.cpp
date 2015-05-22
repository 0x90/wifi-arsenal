/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2008-2011 Steve Glass
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
#include <util/dump.hpp>
#include <util/exceptions.hpp>

#include <algorithm>
#include <pcap.h>

using namespace net;
using namespace std;
using namespace util;

buffer_body::buffer_body(size_t data_sz) :
   data_(new uint8_t[data_sz_]),
   data_sz_(data_sz),
   info_(new buffer_info)
{
   fill(&data_[0], &data_[data_sz_], 0x00);
}

buffer_body::buffer_body(size_t data_sz, const uint8_t *data) :
   data_(new uint8_t[data_sz]),
   data_sz_(data_sz),
   info_(new buffer_info)
{
   copy(&data[0], &data[data_sz_], data_);
}

buffer_body::buffer_body(size_t data_sz, const uint8_t *data, buffer_info_sptr info) :
   data_(new uint8_t[data_sz]),
   data_sz_(data_sz),
   info_(info)
{
   copy(&data[0], &data[data_sz_], data_);
}

buffer_body::~buffer_body()
{
   delete []data_;
}

const uint8_t*
buffer_body::data() const
{
   return data_;
}

size_t
buffer_body::data_size() const
{
   return data_sz_;
}

buffer_info_sptr
buffer_body::info()
{
   return info_;
}

const_buffer_info_sptr
buffer_body::info() const
{
   return info_;
}

const uint8_t*
buffer_body::read_octets(size_t begin, size_t end) const
{
   if(begin < end && end <= data_sz_) {
      return &data_[begin];
   } else {
      ostringstream msg;
      msg <<  "reading [" << begin << "," << end << ") from buffer of size " << data_sz_ << endl;
      msg << hex << setw(2) << setfill('0') << dump(data_sz_, data_) << endl;
      raise<out_of_range>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

void
buffer_body::write_octets(size_t begin, size_t end, const uint8_t octets[])
{
   if(begin < end && end <= data_sz_) {
      copy(&octets[0], &octets[end - begin], &data_[begin]);
   } else {
      ostringstream msg;
      msg << "writing [" << begin << "," << end << ") into buffer of size " << data_sz_ << endl;
      msg << hex << setw(2) << setfill('0') << dump(data_sz_, data_) << endl;
      raise<out_of_range>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}
