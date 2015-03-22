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
#include <net/wnic_require_timestamps.hpp>
#include <net/txtime.hpp>
#include <util/exceptions.hpp>

using namespace net;
using namespace std;
using util::raise;

wnic_require_timestamps::wnic_require_timestamps(wnic_sptr wnic) :
   wnic_wrapper(wnic)
{
}

wnic_require_timestamps::~wnic_require_timestamps()
{
}

buffer_sptr
wnic_require_timestamps::read()
{
   buffer_sptr buf;
   while(buf = wnic_->read()) {
      buffer_info_sptr info(buf->info());
      if(info->has(TIMESTAMP1) && (info->has(TIMESTAMP2)))
         if(info->timestamp1() && info->timestamp2())
            break;
   }
   return buf;
}
