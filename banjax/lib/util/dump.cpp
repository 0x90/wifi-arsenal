/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009 Steve Glass
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

#include <util/dump.hpp>

#include <iostream>
#include <iomanip>

using namespace std;
using namespace util;

dump::dump(size_t octets_sz, const uint8_t *octets) :
   octets_sz_(octets_sz),
   octets_(octets)
{
}

ostream&
dump::write(ostream& os) const
{
   uint16_t w = (os.flags() & ios::hex) ? 2 : 3;
   for(size_t i = 0; i < octets_sz_; ++i) {
      if(0 == (i % 16)) {
         os << endl;
         os << setw(8) << setfill('0') << i << ":";
      } else if (0 == (i % 8)) {
         os << " ";
      }
      os << " " << setw(w) << setfill('0') << static_cast<uint16_t>(octets_[i]);
   }
   os << endl;
   return os;
}
