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

#include <dot11/data_frame.hpp>
#include <dot11/frame_control.hpp>
#include <dot11/llc_hdr.hpp>
#include <net/buffer_fragment.hpp>
#include <util/dump.hpp>
#include <util/exceptions.hpp>

using namespace dot11;
using namespace std;
using namespace net;
using util::dump;
using util::raise;

data_frame::data_frame(buffer_sptr buf) :
   frame(buf)
{
   const size_t min_data_frame_sz = 24;
   if(buf->data_size() < min_data_frame_sz) {
      ostringstream msg;
      msg << "data frame too small (" << buf->data_size() << " <= " << min_data_frame_sz << " octets)";
      msg << hex << setw(2) << setfill('0') << dump(buf->data_size(), buf->data()) << endl;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

data_frame::~data_frame()
{
}

bool
data_frame::has_qos_control() const
{
   frame_control fc(frame::fc());
   const uint8_t QoS_BIT = 0x80;
   return(fc.subtype() & QoS_BIT);
}

// ToDo: QoS control accessor

llc_hdr_sptr
data_frame::get_llc_hdr() const
{
   buffer_sptr b(new buffer_fragment(buf_, mpdu_offset(), buf_->data_size()));
   return llc_hdr_sptr(new llc_hdr(b));
}

size_t
data_frame::mpdu_offset() const
{
   size_t data_ofs = 24;
   if(has_address4())
      data_ofs += 6;
   if(has_qos_control())
      data_ofs += 2;
   return data_ofs /* TEMPORARY KLUDGE */ + 6 /* SKIPS "JUNK" OCTETS */;
}
