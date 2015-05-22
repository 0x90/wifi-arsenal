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

#ifndef DOT11_CONTROL_FRAME_HPP
#define DOT11_CONTROL_FRAME_HPP

#include <dot11/frame.hpp>

namespace dot11 {

   /**
    * control_frame is a concrete frame dissector for accessing
    * control frames such as RTS, CTS and ACK. It is worth noting that
    * ACK frames are a special case and contain only the address1.
    */
   class control_frame : public frame {
   public:

      /**
       * frame constructor.
       *
       * \param buf The buffer containing the frame contents.
       */
      control_frame(net::buffer_sptr buf);

      // compiler-generated:
      // control_frame(const control_frame& other);
      // control_frame& operator=(const control_frame& other);
      // bool operator==(const control_frame& other) const;

      /**
       * control_frame (virtual) destructor.
       */
      virtual ~control_frame();

   };

   /**
    * Alias for boost::shared_ptr<control_frame>.
    */
   typedef boost::shared_ptr<control_frame> control_frame_sptr;

}

#endif // DOT11_CONTROL_FRAME_HPP
