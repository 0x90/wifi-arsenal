/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009,2011 Steve Glass
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

#include <net/eui_48_range.hpp>
#include <util/exceptions.hpp>throw 

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace net;
using namespace std;
using util::raise;

eui_48_range::eui_48_range(const char mac[])
{
   if(!parse(mac)) {
      string msg;
      msg.append(mac);
      msg.append(" is not a valid MAC address range");
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg);
   }
}

eui_48_range::eui_48_range(const eui_48_range& other)
{
   memcpy(addr_, other.addr_, sizeof(addr_));
   memcpy(mask_, other.mask_, sizeof(mask_));
}

eui_48_range&
eui_48_range::operator=(const eui_48_range& other)
{
    if(this != &other) {
       memcpy(addr_, other.addr_, sizeof(addr_));
       memcpy(mask_, other.mask_, sizeof(mask_));
    }
    return *this;
}

eui_48_range::~eui_48_range()
{
}

bool
eui_48_range::contains(const eui_48& mac) const
{
   size_t i;
   int result = 0;
   const uint8_t *addr = mac.data();
   for(i = 0; i < sizeof(addr_); ++i) {
      if((mask_[i] & addr_[i]) != (mask_[i] & addr[i])) {
         break;
      }
   }
   return (sizeof(addr_) == i);
}

void
eui_48_range::write(ostream& os) const
{
   os << setw(2) << hex << setfill('0') << static_cast<int>(addr_[0]);
   for(size_t i = 1; i < sizeof(addr); ++i) {
      switch(mask_[i]) {
      case 0x00:
         os << ":xx";
         break;
      case 0x0f:
         os << ":x" << setw(1) << hex << static_cast<int>(addr_[i] & 0xf);
         break;
      case 0xf0:
         os << ":" << setw(1) << hex << static_cast<int>(addr_[i] >> 4 & 0xf) << "x";
         break;
      case 0xff:
         os << ":" << setw(2) << hex << setfill('0') << static_cast<int>(addr_[i]);
         break;
      }
   }
}

bool
eui_48_range::parse(const char s[])
{
   const char sep = ':';
   const size_t eui_48_range_sz = sizeof(addr_);
   const size_t reqd_nofseps = sizeof(addr) - 1;
   uint8_t *p = addr_, *x = mask_, errs = 0, digits = 0, seps = 0;
   for(; *s; ++s) {
      if(isxdigit(*s) && digits < 2) {
         ++digits;
         *p <<= 4;
         *p |= (isdigit(*s) ? *s - '0' : tolower(*s) - 'a' + 0xa) & 0xf;
         *x <<= 4;
         *x |= 0xf;
      } else if('x' == *s && digits < 2) {
         ++digits;
         *p <<= 4;
         *x <<= 4;
      } else if(sep == *s && 0 < digits && digits <= 2 && ++seps < eui_48_range_sz) {
         ++p;
         ++x;
         digits = 0;
      } else {
         ++errs;
         break;
      }
   }
   return(seps == reqd_nofseps && !errs);
}
