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
#include <net/wnic_timestamp_swizzle.hpp>
#include <net/txtime.hpp>
#include <util/exceptions.hpp>e

using namespace net;
using namespace std;
using util::raise;

wnic_timestamp_swizzle::wnic_timestamp_swizzle(wnic_sptr wnic) :
   wnic_wrapper(wnic)
{
}

wnic_timestamp_swizzle::~wnic_timestamp_swizzle()
{
}

buffer_sptr
wnic_timestamp_swizzle::read()
{
   buffer_sptr buf(wnic_->read());
   if(buf) {
      buffer_info_sptr info(buf->info());
      if(info->has(TIMESTAMP1) ^ (info->has(TIMESTAMP2))) {
         if(info->has(TIMESTAMP1)) {
            uint64_t t = info->timestamp1();
            info->timestamp2(t);
            info->clear(TIMESTAMP1);
         }
         else if(info->has(TIMESTAMP2)) {
            uint64_t t = info->timestamp2();
            info->timestamp1(t);
            info->clear(TIMESTAMP2);
         }        
      }
   }
   return buf;
}
