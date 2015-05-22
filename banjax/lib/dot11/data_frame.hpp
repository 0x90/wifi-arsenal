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

#ifndef DOT11_DATA_FRAME_HPP
#define DOT11_DATA_FRAME_HPP

#include <dot11/frame.hpp>
#include <dot11/llc_hdr.hpp>

namespace dot11 {

   /**
    * data_frame is a concrete, leaf class that represents an IEEE
    * 802.11 data frame.
    */
   class data_frame : public frame {
   public:

      /**
       * data_frame constructor.
       *
       * \param buf A pointer to the data_frame contents.
       */
      explicit data_frame(net::buffer_sptr buf);

      // compiler-generated:
      // data_frame(const data_frame& other);
      // data_frame& operator=(const data_frame& other);
      // bool operator==(const data_frame& other) const;

      /**
       * data_frame destructor.
       */
      virtual ~data_frame();

      /**
       * Tests whether this frame contains a QoS control field.
       *
       * \return true when QoS control is present; otherwise false.
       */
      bool has_qos_control() const;

      // ToDo: add qos_control accessors!

      /**
       * Return a pointer to the LLC header of the payload.
       *
       * \return An llc_hdr_sptr pointing to the frame payload.
       */
      llc_hdr_sptr get_llc_hdr() const;

   protected:

      /**
       * Return the offset of the MPDU. The payload may begin at
       * different addresses depending on whether or not QoS and
       * address4 fields are present.
       *
       * \return The offset of the MPDU within the frame.
       */
      size_t mpdu_offset() const;

   };

   /**
    * Alias for shared_ptr<data_frame>.
    */
   typedef boost::shared_ptr<data_frame> data_frame_sptr;

}

#endif // DOT11_DATA_FRAME_HPP
