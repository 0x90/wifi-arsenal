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

#ifndef NET_EUI_48_RANGE_HPP
#define NET_EUI_48_RANGE_HPP

#include <net/eui_48.hpp>

#include <stdint.h>

namespace net {

   /**
    * A range of IEEE EUI-48 addresses.
    */
   class eui_48_range {
   public:
      explicit eui_48_range(const char mac_str[]);
      eui_48_range(const eui_48_range& other);
      eui_48_range& operator=(const eui_48_range& other);
      ~eui_48_range();
      bool contains(const eui_48& addr) const;
      void write(std::ostream& os) const;
   private:
      bool parse(const char mac[]);
   private:
      typedef uint8_t addr[6];
      addr addr_, mask_;
   };

}

#endif // NET_EUI_48_RANGE_HPP
