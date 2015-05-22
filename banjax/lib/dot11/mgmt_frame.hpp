/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2009,2010 Steve Glass
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

#ifndef DOT11_MGMT_FRAME_HPP
#define DOT11_MGMT_FRAME_HPP

#include <dot11/frame.hpp>

namespace dot11 {

   /**
    * mgmt_frame is a frame subtype representing management frames
    * such as deauthentication, disassociation, probe
    * requests/response and beacons.
    */
   class mgmt_frame : public frame {
   public:

      /**
       * mgmt_frame constructor. Creates a new mgmt_frame using the
       * specified buffer.
       *
       * \param buf A pointer the buffer containing the management frame.
       */
      explicit mgmt_frame(const net::buffer_sptr buf);

      // compiler-generated:
      // mgmt_frame(const mgmt_frame& other);
      // mgmt_frame& operator=(const mgmt_frame& other);
      // bool operator==(const mgmt_frame& other) const;

      /**
       * mgmt_frame (virtual) destructor.
       */
      virtual ~mgmt_frame();

      /**
       * Accessor that returns the value of an 8-bit Information element.
       *
       * \param tag The tag identifying the IE to return.
       * \return The value of the tag.
       * \throws invalid_argument_exception If the value is not present.
       */
      uint8_t IE(uint8_t tag) const;

   };

   /**
    * Alias for shared_ptr<mgmt_frame>.
    */
   typedef boost::shared_ptr<mgmt_frame> mgmt_frame_sptr;

}

#endif // DOT11_MGMT_FRAME_HPP
