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

#define __STDC_CONSTANT_MACROS ON
#include <timespec.hpp>

#include <stdint.h>
#include <time.h>

using namespace util;

timespec
util::operator+(timespec lhs, timespec rhs)
{
   timespec r;
   const int64_t NS_PER_S = INT64_C(1000000000);
   int64_t t = static_cast<int64_t>(lhs.tv_nsec) + static_cast<int64_t>(rhs.tv_nsec); 
   r.tv_sec = lhs.tv_sec + rhs.tv_sec + (t / NS_PER_S);
   r.tv_nsec = t % NS_PER_S;
   return r;
}

timespec
util::operator-(timespec lhs, timespec rhs)
{
   const int64_t NS_PER_S = INT64_C(1000000000);
	// perform the carry for the later subtraction by updating rhs
   if(lhs.tv_nsec < rhs.tv_nsec) {
      int nsec = (rhs.tv_nsec - lhs.tv_nsec) / NS_PER_S + 1;
      rhs.tv_nsec -= NS_PER_S * nsec;
      rhs.tv_sec += nsec;
   }
   if(lhs.tv_nsec - rhs.tv_nsec > 1000000000) {
      int nsec = (lhs.tv_nsec - rhs.tv_nsec) /  NS_PER_S;
      rhs.tv_nsec +=  NS_PER_S * nsec;
      rhs.tv_sec -= nsec;
   }
     
   // perform the subtraction
   timespec r;
   r.tv_sec = lhs.tv_sec - rhs.tv_sec;
   r.tv_nsec = lhs.tv_nsec - rhs.tv_nsec;
   return r;
}

timespec
util::operator*(timespec lhs, uint32_t rhs)
{
   timespec r;
   const int64_t NS_PER_S = INT64_C(1000000000);
   int64_t t = lhs.tv_nsec * rhs;
   r.tv_sec = (lhs.tv_sec * rhs) + (t / NS_PER_S);
   r.tv_nsec = t % NS_PER_S;
   return r;
}
