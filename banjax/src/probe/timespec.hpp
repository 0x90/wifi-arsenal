/* -*- mode: C++; tab-width: 3; -*- */

/*
 * Copyright 2011 Steve Glass
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

#ifndef UTIL_TIMESPEC_HPP
#define UTIL_TIMESPEC_HPP

#include <stdint.h>
#include <time.h>

namespace util {

	/**
    * Add rhs to lhs timespec and return the result.
    *
    * \param lhs A timespec.
    * \param rhs A timespec.
    * \return The result of adding rhs to lhs.
    */
   extern timespec operator+(timespec lhs, timespec rhs);

	/**
    * Subtract rhs from lhs timespec and return the result.
    *
    * \param lhs A timespec.
    * \param rhs A timespec.
    * \return The result of subtracting rhs from lhs.
    */
   extern timespec operator-(timespec lhs, timespec rhs);

	/**
    * Multiply rhs by the lhs timespec and return the result.
    *
    * \param lhs A timespec.
    * \param rhs The multiplication factor.
    * \return The result of multiplying lhs by rhs.
    */
   extern timespec operator*(timespec lhs, uint32_t rhs);

}

#endif /* UTIL_TIMESPEC_HPP */
