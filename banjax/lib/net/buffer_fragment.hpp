/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2008-2011 Steve Glass
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

#ifndef NET_BUFFER_FRAGMENT_HPP
#define NET_BUFFER_FRAGMENT_HPP

#include <net/abstract_buffer.hpp>

namespace net {

   /**
    * buffer_fragment represents a bounds-checked fragment of another
    * buffer object. Attempting to write beyond the boundaries of the
    * fragment will result in an out_of_range exception being raised.
    */
   class buffer_fragment : public abstract_buffer {
   public:

      /**
       * Construct a buffer_fragment from buf.
       * 
       * \param buf A non-null buffer_sptr pointing to a buffer object.
       */
      buffer_fragment(buffer_sptr buf);

      /**
       * Construct a buffer_fragment buf[begin,end).
       * 
       * \param buf A non-null buffer_sptr pointing to a buffer object.
       * \param begin The index of the first element in the fragment.
       * \param end The index of the last element in the fragment.
       */
      buffer_fragment(buffer_sptr buf, size_t begin, size_t end);

      /**
       * (Virtual) buffer_fragment destructor.
       */
      virtual ~buffer_fragment();

      /**
       * Return a pointer to the beginning of the buffer_fragment.
       *
       * \return A non-null pointer to the buffer_fragment.
       */
      virtual const uint8_t *data() const;

      /**
       * Return the size of this buffer in octets.
       *
       * \return The size of the buffer_body.
       */
      virtual size_t data_size() const;

      /**
       * Returns the buffer_info associated with this buffer. This is
       * the non-const accessor which allows callers to modify the
       * returned buffer_info.
       *
       * \return A (possibly null) buffer_info_sptr.
       */
      virtual buffer_info_sptr info();

      /**
       * Returns the buffer_info associated with this buffer. This is
       * the const accessor which does not allow callers to modify the
       * returned buffer_info.
       *
       * \return A (possibly null) const_buffer_info_sptr.
       */
      virtual const_buffer_info_sptr info() const;

      /**
       * Return a pointer to the beginning of a block from
       * [begin,end). The specified block must lie wholly within the
       * buffer or else an out_of_bounds exception will be raised.
       *
       * \param i The offset from which tor read.
       * \return A uint32_t containing the value at position i.
       */
      virtual const uint8_t *read_octets(size_t begin, size_t end) const;

      /**
       * Writes an octet string at positions [begin,end). The
       * specified block must lie wholly within this object or else an
       * out_of_bounds exception will be raised.
       *
       * \param i The offset from which tor read.
       * \param octets A non-NULL pointer to octet string to write.
       */
      void write_octets(size_t begin, size_t end, const uint8_t *bytes);

   private:

      /**
       * The underlying buffer.
       */
      buffer_sptr buf_;

      /**
       * The index of the first element.
       */
      size_t begin_;

      /**
       * The index of the last element.
       */
      size_t end_;

   };

}

#endif // NET_BUFFER_FRAGMENT_HPP
