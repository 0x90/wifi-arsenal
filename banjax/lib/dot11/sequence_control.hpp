/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009, 2010 Steve Glass
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

#ifndef DOT11_SEQUENCE_CONTROL_HPP
#define DOT11_SEQUENCE_CONTROL_HPP

#include <stdint.h>

namespace dot11 {

   /**
    * sequence_control is a concrete dissector class that provides
    * access to the IEEE 802.11 sequence control field.
    */
   class sequence_control {
   public:
      sequence_control(uint16_t sc);
      // compiler-generated:
      // sequence_control(const sequence_control& other);
      // sequence_control(sequence_control& other);
      // ~sequence_control();
      uint8_t fragment_no() const;
      void fragment_no(uint8_t u);
      uint16_t sequence_no() const;
      void sequence_no(uint16_t u);
      operator uint16_t() const;
   private:
      uint16_t sc_;
   };

}

#endif // DOT11_SEQUENCE_CONTROL_HPP
