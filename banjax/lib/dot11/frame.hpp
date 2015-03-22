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

#ifndef DOT11_FRAME_HPP
#define DOT11_FRAME_HPP


#include <net/buffer.hpp>
#include <dot11/frame_control.hpp>
#include <dot11/sequence_control.hpp>

#include <boost/shared_ptr.hpp>

namespace dot11 {

   /**
    * Frame is a simple dissector class that represents all possible
    * IEEE 802.11 frame types. Concrete frame objects can be
    * instantiated and, if necessary, converted to more specific
    * frame sub-types for further processing.
    */
   class frame {
   public:

      /**
       * frame constructor.
       *
       * \param buf The buffer containing the frame contents.
       */
      explicit frame(net::buffer_sptr buf);

      // compiler-generated:
      // frame(const frame& other);
      // frame& operator=(const frame& other);
      // bool operator==(const frame& other) const;

      /**
       * frame (virtual) destructor.
       */
      virtual ~frame();

      /**
       * frame_control accessor that returns a copy of the frame_control
       * field from the 802.11 frame header.
       *
       * \return A frame_control object.
       */
      frame_control fc() const;

      /**
       * Duration accessor that returns a uint16_t containing the
       * value of the duration field. Refer to the spec to see how the
       * high-order two bits determine how this value should be
       * interpreted.
       *
       * \returns A uint16_t containing the 802.11 frame duration.
       */
      uint16_t duration() const;

      /**
       * Accessor that returns the frame's address1 value.
       *
       * \return An eui_48 object containing the address1 value.
       */
      net::eui_48 address1() const;

      /**
       * Tests whether this frame contains an address2 field.
       *
       * \return true when address2 is present; otherwise false.
       */
      bool has_address2() const;

      /**
       * Accessor that returns the frame's address2 value.
       *
       * \return An eui_48 object containing the address2 value.
       */
      net::eui_48 address2() const;

      /**
       * Tests whether this frame contains an address3 field.
       *
       * \return true when address3 is present; otherwise false.
       */
      bool has_address3() const;

      /**
       * Accessor that returns the frame's address3 value.
       *
       * \return An eui_48 object containing the address3 value.
       */
      net::eui_48 address3() const;

      /**
       * Accessor that return the frame's sequence control field.
       *
       * \return A sequence_control object containing the sc field.
       */
      sequence_control sc() const;

      /**
       * Tests whether this frame contains an address4 field.
       *
       * \return true when address4 is present; otherwise false.
       */
      bool has_address4() const;

      /**
       * Accessor that returns the frame's address4 value.
       *
       * \return An eui_48 address for the specified field
       * \throws logic_error If has_address4() is false.
       */
      net::eui_48 address4() const;

      /**
       * If this object represents a control frame then return a
       * pointer to a control_frame object; otherwise return
       * NULL. This is *not* a down-cast because frame instances can
       * exist in their own right.
       *
       * \return A (possibly NULL) pointer to a control_frame.
       */
      boost::shared_ptr<class control_frame> as_control_frame();

      /**
       * If this object represents a data frame then return a
       * pointer to a control_frame object; otherwise return
       * NULL. This is *not* a down-cast because frame instances can
       * exist in their own right.
       *
       * \return A (possibly NULL) pointer to a data_frame.
       */
      boost::shared_ptr<class data_frame> as_data_frame();

      /**
       * If this object represents a control frame then return a
       * pointer to a mgmt_frame object; otherwise return
       * NULL. This is *not* a down-cast because frame instances can
       * exist in their own right.
       *
       * \return A (possibly NULL) pointer to a mgmt_frame.
       */
      boost::shared_ptr<class mgmt_frame> as_mgmt_frame();

   protected:

      /**
       * Pointer to a buffer that holds the frame contents.
       */
      net::buffer_sptr buf_;

   };

   /**
    * Alias for boost::shared_ptr<frame>.
    */
   typedef boost::shared_ptr<frame> frame_sptr;

}

#endif // DOT11_FRAME_HPP
