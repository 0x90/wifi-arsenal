/* -*- mode: C++ -*- */

/*
 * Copyright 2010-2011 Steve Glass
 * 
 * This file is part of banjax.
 * 
 * banjax is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * banjax is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with banjax; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Boston, MA
 * 02110-1301, USA.
 */

#ifndef INCLUDED_UTIL_EXCEPTIONS_H
#define INCLUDED_UTIL_EXCEPTIONS_H

#include <util/syscall_error.hpp>

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace util
{

   /**
    * Raise an exception of type T with the given error message.
    *
    * \param func The name of the function in error.
    * \param file The name of the file.
    * \param line The line number where the error originated.
    * \param text A string describing the error.
    */
   template<class T>
   void raise(const char *func, const char *file, int line, std::string text) {
      std::ostringstream msg;
      msg << "Error: " << text << std::endl;
      msg << " Func: " << func << std::endl;
      msg << " File: " << file << std::endl;
      msg << " Line: " << line << std::endl << std::endl;
      throw T(msg.str());
   }

}

#define CHECK(C) \
   if(!(C)) { \
      util::raise<std::invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, #C); \
   }

#define CHECK_NOT_NULL(P) \
   if(!P) { \
      util::raise<std::invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, "NULL pointer"); \
   }

#define CHECK_EQUAL(A,E) \
   if(!(A == E)) { \
      util::raise<std::invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, #A " != " #E ); \
   }

#define CHECK_NOT_EQUAL(A,E) \
   if(A == E) {                                                        \
      util::raise<std::invalid_argument>(__PRETTY_FUNCTION__, __FILE__, __LINE__, #A " == " #E); \
   }

#define CHECK_SIZE(ACTUAL_SZ, EXPECTED_SZ) \
   if(ACTUAL_SZ != EXPECTED_SZ) { \
      std::ostringstream text; \
      text << "size " << ACTUAL_SZ << " is not the expected size " << EXPECTED_SZ << std::endl; \
      util::raise<std::length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, text.str()); \
   }

#define CHECK_MIN_SIZE(ACTUAL, MIN) \
   if(ACTUAL < MIN) { \
      std::ostringstream text; \
      text << ACTUAL << " is less than the expected minimum " << MIN << std::endl; \
      util::raise<std::length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, text.str()); \
   }

#define CHECK_MAX_SIZE(ACTUAL, MAX) \
   if(ACTUAL > MAX) { \
      std::ostringstream text; \
      text << ACTUAL << " exceeds the expected maximum " << MAX << std::endl; \
      util::raise<std::length_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, text.str()); \
   }

#define CHECK_RANGE(MIN, VALUE, MAX) \
   if(!((MIN <= VALUE) && (VALUE < MAX))) { \
      std::ostringstream text; \
      text << "value " << VALUE << " is outside valid range " << MIN << " <= X < " << MAX << std::endl; \
      util::raise<std::out_of_range>(__PRETTY_FUNCTION__, __FILE__, __LINE__, text.str()); \
   }

#define PRECONDITION(C) \
   if(!(C)) { \
      util::raise<std::logic_error>(__PRETTY_FUNCTION__, __FILE__, __LINE__, "precondition fail " #C); \
   }

#endif /* INCLUDED_UTIL_EXCEPTIONS_H */
