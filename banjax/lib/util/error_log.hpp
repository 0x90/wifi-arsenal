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

#ifndef UTIL_ERROR_LOG_HPP
#define UTIL_ERROR_LOG_HPP

#include <exception>

namespace util {
   class error_log {
   public:
      static error_log& get();
      // compiler_generated:
      // error_log();
      // error_log(const error_log& other);
      // error_log& operator=(const error_log& other);
      // ~error_log();
      void log_unhandled(const char *func, const char *file, int line);
      void log_unhandled(const char *func, const char *file, int line, const std::exception& x);
   };
}

#endif // UTIL_ERROR_LOG_HPP
