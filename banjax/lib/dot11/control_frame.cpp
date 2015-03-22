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

#include <dot11/control_frame.hpp>
#include <util/dump.hpp>
#include <util/exceptions.hpp>

using namespace dot11;
using namespace std;
using net::buffer_sptr;
using util::dump;
using util::raise;

control_frame::control_frame(buffer_sptr buf) :
   frame(buf)
{
   const size_t min_data_frame_sz = 10; // sizeof(ACK_frame)
   if(buf->data_size() < min_data_frame_sz) {
      ostringstream msg;
      msg << "control frame too small (" << buf->data_size() << " <= " << min_data_frame_sz << " octets)";
      msg << hex << setw(2) << setfill('0') << dump(buf->data_size(), buf->data()) << endl;
      raise<length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

control_frame::~control_frame()
{
}
