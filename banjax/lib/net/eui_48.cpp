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

#include <net/eui_48.hpp>
#include <net/eui_48_range.hpp>
#include <util/exceptions.hpp>

#include <algorithm>
#include <cstring> // for memcmp!
#include <boost/bind.hpp>

using namespace net;
using namespace std;
using boost::bind;
using util::raise;

eui_48::eui_48()
{
   fill(&addr_[0], &addr_[MAC_SZ], 0xff);
}

eui_48::eui_48(const char *mac, char sep)
{
   CHECK_NOT_NULL(mac);
   CHECK(sep == ':' || sep == '-');
   const size_t eui_48_sz = MAC_SZ;
   const size_t reqd_nofseps = MAC_SZ - 1;
   uint8_t *p = addr_, errs = 0, digits = 0, seps = 0;
   fill(&addr_[0], &addr_[MAC_SZ], 0x00);
   for(const char *s = mac; *s; ++s) {
      if(isxdigit(*s) && digits < 2) {
         ++digits;
         *p <<= 4;
         *p |= (isdigit(*s) ? *s - '0' : tolower(*s) - 'a' + 0xa);
      } else if(sep == *s && (0 < digits && digits <= 2) && ++seps < eui_48_sz) {
         ++p;
         digits = 0;
      } else {
         ++errs;
         break;
      }
   }
   if(errs || seps != reqd_nofseps) {
      ostringstream msg;
      msg << mac << " is not a valid MAC address" << endl;
      raise<invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, msg.str());
   }
}

eui_48::eui_48(size_t mac_sz, const uint8_t *mac)
{
   CHECK_EQUAL(MAC_SZ, mac_sz);
   CHECK_NOT_NULL(mac);
   copy(&mac[0], &mac[mac_sz], addr_);
}

eui_48::eui_48(const eui_48& other)
{
   copy(&other.addr_[0], &other.addr_[MAC_SZ], addr_);
}

eui_48&
eui_48::operator=(const eui_48& other)
{
    if(this != &other) {
       copy(&other.addr_[0], &other.addr_[MAC_SZ], addr_);
    }
    return *this;
}

eui_48::~eui_48()
{
}

bool
eui_48::operator==(const eui_48& other) const
{
   return memcmp(addr_, other.addr_, MAC_SZ) == 0;
}

bool
eui_48::operator<(const eui_48& other) const
{
   return memcmp(addr_, other.addr_, MAC_SZ) < 0;
}

eui_48
eui_48::operator&(const eui_48& other)
{
   uint8_t a[MAC_SZ];
   for(size_t i = 0; i < MAC_SZ; ++i) {
      a[i] = addr_[i] & other.addr_[i];
   }
   return eui_48(MAC_SZ, a);
}

const uint8_t*
eui_48::data() const
{
    return addr_;
}

size_t
eui_48::data_size() const
{
   return MAC_SZ;
}

size_t
eui_48::hash() const
{
   return addr_[2] << 24 | addr_[3] << 16 | addr_[4] << 8 | addr_[5];
}

void
eui_48::write(ostream& os) const
{
   ios_base::fmtflags save = os.flags();
   os << setw(2) << hex << setfill('0') << static_cast<int>(addr_[0]);
   for(size_t i = 1; i < MAC_SZ; ++i) {
      os << ":" << setw(2) << hex << setfill('0') << static_cast<uint16_t>(addr_[i]);
   }
   os.flags(save);
}

bool
eui_48::is_multicast() const
{
   const uint8_t multicast_bit = 0x01;
   return addr_[0] & multicast_bit;
}

bool
eui_48::is_special() const
{
   static const eui_48_range specials[] = {
      eui_48_range("ff:ff:ff:ff:ff:ff"),
      eui_48_range("33:33:xx:xx:xx:xx"),
      eui_48_range("01:00:5e:xx:xx:xx")
   };
   const size_t nof_specials = sizeof(specials) / sizeof(specials[0]);
   return find_if(&specials[0], &specials[nof_specials], bind(&eui_48_range::contains, _1, *this)) != &specials[nof_specials];
}

bool
eui_48::is_unicast() const
{
   const uint8_t multicast_bit = 0x01;
   return (addr_[0] & multicast_bit) == 0;
}

size_t
hash(const eui_48& addr)
{
   return addr.hash();
}

ostream&
net::operator<<(ostream& os, const eui_48& addr)
{
   addr.write(os);
   return os;
}
