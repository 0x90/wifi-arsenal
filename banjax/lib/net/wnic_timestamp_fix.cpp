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
#include <net/wnic_timestamp_fix.hpp>
#include <net/txtime.hpp>
#include <util/exceptions.hpp>

using namespace net;
using namespace std;
using util::raise;

wnic_timestamp_fix::wnic_timestamp_fix(wnic_sptr wnic) :
   wnic_wrapper(wnic)
{
}

wnic_timestamp_fix::~wnic_timestamp_fix()
{
}

buffer_sptr
wnic_timestamp_fix::read()
{
   buffer_sptr buf(wnic_->read());
   if(buf) {
      buffer_info_sptr info(buf->info());
      if(info->has(TIMESTAMP1 | TIMESTAMP2)) {
         // nothing to do!
      } else if(info->has(RATE_Kbs | CHANNEL_FLAGS) && (info->has(TIMESTAMP1) || info->has(TIMESTAMP2))) {
         // guard against MadWifi giving us a rate of 0Kb/s
         uint32_t rate_Kbs = info->rate_Kbs();
         encoding_sptr enc(info->channel_encoding());
         if(!rate_Kbs) {
            rate_Kbs = enc->default_rate();
         }
         // compute txtime
         uint32_t t = 0;
         const uint32_t CRC_SZ = 4;
         bool has_short_preamble = info->channel_flags() & CHANNEL_PREAMBLE_SHORT;
         t = enc->txtime(buf->data_size() + CRC_SZ, rate_Kbs, has_short_preamble);
         // adjust timestamp
         if(info->has(TIMESTAMP1)) {
            info->timestamp2(info->timestamp1() + t);
         } else if(info->has(TIMESTAMP2)) {
            info->timestamp1(info->timestamp2() - t);
         }
      } else {
         ostringstream msg;
         msg << "cannot fix timestamp (" << *info << ")" << endl;
         raise<runtime_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
      }
   }
   return buf;
}
