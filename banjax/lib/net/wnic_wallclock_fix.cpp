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

#define __STDC_CONSTANT_MACROS
#include <net/buffer.hpp>
#include <net/buffer_info.hpp>
#include <net/wnic_wallclock_fix.hpp>
#include <util/exceptions.hpp>

#include <sys/time.h>

using namespace net;
using namespace std;

wnic_wallclock_fix::wnic_wallclock_fix(wnic_sptr wnic) :
   wnic_wrapper(wnic)
{
}

wnic_wallclock_fix::~wnic_wallclock_fix()
{
}

buffer_sptr
wnic_wallclock_fix::read()
{
   buffer_sptr buf(wnic_->read());
   if(buf) {
      buffer_info_sptr info(buf->info());
      if(!info->has(TIMESTAMP_WALLCLOCK)) {
         struct timeval ts;
         gettimeofday(&ts, NULL);
         info->timestamp_wallclock((ts.tv_sec * UINT64_C(1000000)) + ts.tv_usec);
      }
   }
   return buf;
}
