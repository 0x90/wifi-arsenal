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

#include <net/buffer.hpp>
#include <net/buffer_info.hpp>
#include <net/encoding.hpp>
#include <net/wnic_encoding_fix.hpp>
#include <net/txtime.hpp>
#include <util/exceptions.hpp>

using namespace net;
using namespace std;
using boost::shared_ptr;
using util::raise;

wnic_encoding_fix::wnic_encoding_fix(wnic_sptr wnic, flags_t default_channel_flags) :
   wnic_wrapper(wnic),
   default_channel_flags_(default_channel_flags)
{
}

wnic_encoding_fix::~wnic_encoding_fix()
{
}

buffer_sptr
wnic_encoding_fix::read()
{
   buffer_sptr buf(wnic_->read());
   if(buf) {
      buffer_info_sptr info(buf->info());
      if(! info->has(CHANNEL_FLAGS)) {
         info->channel_flags(default_channel_flags_);
      }
   }
   return buf;
}
