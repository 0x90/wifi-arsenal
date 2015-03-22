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

#ifndef NET_BUFFER_BODY_HPP
#define NET_BUFFER_BODY_HPP

#include <net/abstract_buffer.hpp>

namespace net {

   /**
    * buffer_body is a concrete class that implements an in-memory
    * buffer. Accesses to the buffer contents are bounds-checked and
    * an out_of_range exception thrown for any attempt to access
    * memory outside the buffer bounds.
    */
   class buffer_body : public abstract_buffer {
   public:

      /**
       * Construct a buffer_body of a given size. The buffer_body contents are
       * initialized to zeroes.
       * 
       * \param data_sz The size of the buffer_body.
       */
      explicit buffer_body(size_t data_sz);

      /**
       * Construct a buffer_body of a given size and intialize it from the
       * specified data.
       * 
       * \param data_sz The size of the buffer_body.
       * \param data A non-null pointer to the initial buffer_body contents.
       */
      buffer_body(size_t data_sz, const uint8_t *data);

      /**
       * Construct a buffer_body of a given size and intialize it from the
       * specified data.
       * 
       * \param data_sz The size of the buffer_body.
       * \param data A non-null pointer to the initial buffer_body contents.
       * \param info A non-null buffer_sptr pointing to the buffer_info.
       */
      buffer_body(size_t data_sz, const uint8_t *data, buffer_info_sptr info);

      /**
       * buffer_body destructor.
       */
      virtual ~buffer_body();

      /**
       * Return a pointer to the begiinig of this buffer.
       *
       * \return A non-null pointer to the buffer memory.
       */
      virtual const uint8_t *data() const;

      /**
       * Return the size of this buffer in octets. Banjax never
       * includes the FCS for a frame and so the buffer is 4 octets
       * smaller than the actual frame that is sent over the air.
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
       * buffer_body or else an out_of_bounds exception will be
       * raised.
       *
       * \param i The offset from which tor read.
       * \return A uint32_t containing the value at position i.
       */
      const uint8_t *read_octets(size_t begin, size_t end) const;

      /**
       * Writes an octet string into the buffer at positions
       * [begin,end). The specified block must lie wholly within the
       * buffer or else an out_of_bounds exception will be raised.
       *
       * \param i The offset from which tor read.
       * \param octets A non-NULL pointer to octet string to write.
       */
      void write_octets(size_t begin, size_t end, const uint8_t octets[]);

   private:

      /**
       * The size of the buffer_body.
       */
      size_t data_sz_;

      /**
       * The buffer_body content.
       */
      uint8_t *data_;

      /**
       * Info about this buffer instance.
       */
      buffer_info_sptr info_;

   };

}

#endif // NET_BUFFER_BODY_HPP
