/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009-2011 Steve Glass
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

#include <dot11/mgmt_frame.hpp>
#include <util/dump.hpp>
#include <util/exceptions.hpp>

using namespace dot11;
using namespace std;
using net::buffer_sptr;
using net::eui_48;
using std::string;
using util::dump;
using util::raise;


mgmt_frame::mgmt_frame(buffer_sptr buf) :
   frame(buf)
{
   const size_t min_mgmt_frame_sz = 24;
   if(buf->data_size() < min_mgmt_frame_sz) {
      ostringstream msg;
      msg << "management frame too small (" << buf->data_size() << " <= " << min_mgmt_frame_sz << " octets)";
      msg << hex << setw(2) << setfill('0') << dump(buf->data_size(), buf->data()) << endl;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

mgmt_frame::~mgmt_frame()
{
}

uint8_t
mgmt_frame::IE(uint8_t tag) const
{
   uint8_t tag_size;
   size_t frame_sz = buf_->data_size();
   for(size_t i = 0x24; i < frame_sz; i += tag_size) {
      const uint8_t t = buf_->read_u8(i);
      const uint8_t l = buf_->read_u8(i+1);
      if(t == tag && l == 1) {
         return buf_->read_u8(i+2);
      }
      tag_size = l + 2;
   }
   ostringstream msg;
   msg << "unknown IE  (tag=" << hex << setw(2) << setfill('0') << tag << ")";
   msg << hex << setw(2) << setfill('0') << dump(buf_->data_size(), buf_->data()) << endl;
   raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
}
