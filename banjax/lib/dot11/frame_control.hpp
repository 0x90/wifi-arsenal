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

#ifndef DOT11_FRAME_CONTROL_HPP
#define DOT11_FRAME_CONTROL_HPP

#include <dot11/frame_subtype.hpp>
#include <dot11/frame_type.hpp>

#include <stdint.h>

namespace dot11 {

   /**
    * frame_control is a concrete dissector class that provides access
    * to the IEEE 802.11 frame control bitfield. Accessors are
    * provided which perform the bit-shift and masking required for
    * each field.
    */
   class frame_control {
   public:
      frame_control(uint16_t fc = 0);
      // compiler-generated:
      // frame_control(const frame_control& other);
      // frame_control& operator=(frame_control& other);
      // bool operator==(const frame_control& other);
      // ~frame_control();
      uint8_t version() const;
      void version(uint8_t v);
      frame_type type() const;
      void type(frame_type t);
      frame_subtype subtype() const;
      void subtype(frame_subtype t);
      bool to_ds() const;
      void to_ds(bool b);
      bool from_ds() const;
      void from_ds(bool b);
      bool more_frag() const;
      void more_frag(bool b);
      bool retry() const;
      void retry(bool b);
      bool pwr_mgt() const;
      void pwr_mgt(bool b);
      bool more_data() const;
      void more_data(bool b);
      bool protected_frame() const;
      void protected_frame(bool b);
      bool order() const;
      void order(bool b);
      operator uint16_t() const;
   private:
      uint16_t fc_;
   };

}

#endif // DOT11_FRAME_CONTROL_HPP
