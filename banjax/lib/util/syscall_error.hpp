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

#ifndef UTIL_SYSCALL_ERROR_HPP
#define UTIL_SYSCALL_ERROR_HPP

#include <cerrno>
#include <stdexcept>

namespace util
{
   class syscall_error : public std::runtime_error
   {
   public:
      syscall_error(const std::string& msg);
      // compiler-generated:
      // syscall_error(const syscall_error& other);
      // syscall_error& syscall_error(const syscall_error& other);
      // ~syscall_error();
   };
}

#endif // UTIL_SYSCALL_ERROR_HPP
