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

#ifndef UTIL_BYTESWAB_HPP
#define UTIL_BYTESWAB_HPP

namespace util {

	/**
    * Copy an integer object of type T into a buffer using little-endian format.
    *
    * \param in The value to encode.
    * \param out A non-null pointer to a buffer at least sizeof(T) octets long.
    *
    */
   template <typename T>
   void cpu_to_le(T in, uint8_t *out)
   {
      T t = in;
      const size_t nof_octets = sizeof(T);
      for(size_t i = 0; i < nof_octets; ++i) {
         *out++ = (t >> (i * 8)) & 0xff;
      }
   }

	/**
    * Copy an integer object of type T into a buffer using big-endian format.
    *
    * \param in The value to encode.
    * \param out A non-null pointer to a buffer at least sizeof(T) octets long.
    *
    */
   template <typename T>
   void cpu_to_be(T in, uint8_t *out)
   {
      T t = in;
      const size_t nof_octets = sizeof(T);
      for(size_t i = 0; i < nof_octets; ++i) {
         *out++ = (t >> ((nof_octets - i - 1) * 8)) & 0xff;
      }
   }

	/**
    * Copy an integer object of type T from a buffer in little-endian format.
    *
    * \param  in A non-null pointer to a buffer at least sizeof(T) octets long.
    * \return The decoded integer value.
    *
    */
   template <typename T>
   void le_to_cpu(const uint8_t *in, T& out)
   {
      T t = 0;
      const size_t nof_octets = sizeof(T);
      for(size_t i = 0; i < nof_octets; ++i) {
         t += static_cast<T>(*in++) << (i * 8);
      }
      out = t;
   }

	/**
    * Copy an integer object of type T from a buffer in big-endian format.
    *
    * \param  in A non-null pointer to a buffer at least sizeof(T) octets long.
    * \return The decoded integer value.
    *
    */
   template <typename T>
   void be_to_cpu(const uint8_t *in, T& out)
   {
      T t = 0;
      const size_t nof_octets = sizeof(T);
      for(size_t i = 0; i < nof_octets; ++i) {
         t += static_cast<T>(*in++) << ((nof_octets - i - 1) * 8);
      }
      out = t;
   }

}

#endif /* UTIL_BYTESWAB_HPP */
